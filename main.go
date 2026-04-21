// AIFV-Scanner - Standalone AI Infrastructure Fingerprint & Vulnerability Scanner
// Extracted from AI-Infra-Guard (https://github.com/Tencent/AI-Infra-Guard)
// by Tencent Zhuque Lab
package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/parser"
	"github.com/Tencent/AI-Infra-Guard/common/fingerprints/preload"
	"github.com/Tencent/AI-Infra-Guard/common/utils"
	"github.com/Tencent/AI-Infra-Guard/pkg/httpx"
	"github.com/Tencent/AI-Infra-Guard/pkg/vulstruct"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/remeh/sizedwaitgroup"
)

//go:embed all:static
var staticFS embed.FS

// ScanRequest represents a scan task request
type ScanRequest struct {
	Targets  []string `json:"targets" binding:"required"`
	Timeout  int      `json:"timeout"`
	Language string   `json:"language"`
}

// ScanResult represents a single target scan result
type ScanResult struct {
	TargetURL       string             `json:"target_url"`
	StatusCode      int                `json:"status_code"`
	Title           string             `json:"title"`
	Fingerprints    []preload.FpResult `json:"fingerprints"`
	Vulnerabilities []vulstruct.Info   `json:"vulnerabilities"`
	ResponseTime    string             `json:"response_time"`
	Error           string             `json:"error,omitempty"`
}

// ScanTask tracks the state of a scan task
type ScanTask struct {
	ID        string       `json:"id"`
	Status    string       `json:"status"` // running, completed, failed
	Targets   []string     `json:"targets"`
	Total     int          `json:"total"`
	Current   int          `json:"current"`
	Results   []ScanResult `json:"results"`
	StartTime time.Time    `json:"start_time"`
	Error     string       `json:"error,omitempty"`
	mu        sync.Mutex
}

// ScanEngine wraps the fingerprint and vulnerability engines
type ScanEngine struct {
	fpEngine    *preload.Runner
	advEngineZh *vulstruct.AdvisoryEngine
	advEngineEn *vulstruct.AdvisoryEngine
	hp          *httpx.HTTPX
	fps         []parser.FingerPrint
	fpDir       string
	vulDir      string
	vulDirEn    string
	mu          sync.RWMutex
}

var (
	engine *ScanEngine
	tasks  = sync.Map{}
)

func newScanEngine(fpDir, vulDir, vulDirEn string, timeout int) (*ScanEngine, error) {
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("create dialer: %w", err)
	}

	httpOptions := &httpx.HTTPOptions{
		Timeout:          time.Duration(timeout) * time.Second,
		RetryMax:         1,
		FollowRedirects:  true,
		Unsafe:           false,
		DefaultUserAgent: httpx.GetRandomUserAgent(),
		Dialer:           dialer,
	}

	hp, err := httpx.NewHttpx(httpOptions)
	if err != nil {
		return nil, fmt.Errorf("create http client: %w", err)
	}

	se := &ScanEngine{
		hp:       hp,
		fpDir:    fpDir,
		vulDir:   vulDir,
		vulDirEn: vulDirEn,
	}

	if err := se.loadFingerprints(); err != nil {
		return nil, err
	}
	if err := se.loadVulnerabilities(); err != nil {
		return nil, err
	}

	return se, nil
}

func (se *ScanEngine) loadFingerprints() error {
	fps := make([]parser.FingerPrint, 0)
	files, err := utils.ScanDir(se.fpDir)
	if err != nil {
		return fmt.Errorf("scan fingerprint dir: %w", err)
	}
	for _, filename := range files {
		if !strings.HasSuffix(filename, ".yaml") {
			continue
		}
		data, err := os.ReadFile(filename)
		if err != nil {
			log.Printf("WARN: read fingerprint file %s: %v", filename, err)
			continue
		}
		fp, err := parser.InitFingerPrintFromData(data)
		if err != nil {
			log.Printf("WARN: parse fingerprint file %s: %v", filename, err)
			continue
		}
		fps = append(fps, *fp)
	}
	se.mu.Lock()
	se.fps = fps
	se.fpEngine = preload.New(se.hp, fps)
	se.mu.Unlock()
	log.Printf("Loaded %d fingerprints", len(fps))
	return nil
}

func (se *ScanEngine) loadVulnerabilities() error {
	// Load Chinese
	zhEngine := vulstruct.NewAdvisoryEngine()
	if err := zhEngine.LoadFromDirectory(se.vulDir); err != nil {
		return fmt.Errorf("load vulnerabilities (zh): %w", err)
	}
	// Load English
	enEngine := vulstruct.NewAdvisoryEngine()
	if se.vulDirEn != "" {
		if _, err := os.Stat(se.vulDirEn); err == nil {
			if err := enEngine.LoadFromDirectory(se.vulDirEn); err != nil {
				log.Printf("WARN: load vulnerabilities (en): %v", err)
			}
		}
	}
	se.mu.Lock()
	se.advEngineZh = zhEngine
	se.advEngineEn = enEngine
	se.mu.Unlock()
	log.Printf("Loaded %d vulnerability rules (zh), %d (en)", zhEngine.GetCount(), enEngine.GetCount())
	return nil
}

func (se *ScanEngine) getAdvEngine(lang string) *vulstruct.AdvisoryEngine {
	if lang == "en" && se.advEngineEn != nil && se.advEngineEn.GetCount() > 0 {
		return se.advEngineEn
	}
	return se.advEngineZh
}

func (se *ScanEngine) scanTarget(target, lang string) ScanResult {
	se.mu.RLock()
	fpEngine := se.fpEngine
	advEngine := se.getAdvEngine(lang)
	hp := se.hp
	se.mu.RUnlock()

	result := ScanResult{TargetURL: target}

	fullUrl := target
	if !strings.HasPrefix(target, "http") {
		fullUrl = "http://" + target
	}

	timeStart := time.Now()
	resp, err := hp.Get(fullUrl, nil)
	if err != nil {
		result.TargetURL = fullUrl
		result.Error = err.Error()
		return result
	}
	result.ResponseTime = time.Since(timeStart).String()
	result.TargetURL = fullUrl
	result.StatusCode = resp.StatusCode
	result.Title = resp.Title

	iconData, _ := utils.GetFaviconBytes(hp, fullUrl, resp.Data)
	faviconHash := utils.FaviconHash(iconData)

	fpResults := fpEngine.RunFpReqs(fullUrl, 10, faviconHash)
	result.Fingerprints = fpResults

	vuls := make([]vulstruct.Info, 0)
	for _, fp := range fpResults {
		advisories, err := advEngine.GetAdvisories(fp.Name, fp.Version, true)
		if err != nil {
			continue
		}
		for _, ad := range advisories {
			vuls = append(vuls, ad.Info)
		}
	}
	result.Vulnerabilities = vuls

	return result
}

// API Handlers

func handleScan(c *gin.Context) {
	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	lang := req.Language
	if lang == "" {
		lang = "zh"
	}

	taskID := uuid.New().String()[:8]
	task := &ScanTask{
		ID:        taskID,
		Status:    "running",
		Targets:   req.Targets,
		Total:     len(req.Targets),
		Current:   0,
		Results:   make([]ScanResult, 0),
		StartTime: time.Now(),
	}
	tasks.Store(taskID, task)

	go func() {
		wg := sizedwaitgroup.New(20)
		for _, target := range req.Targets {
			wg.Add()
			go func(t string) {
				defer wg.Done()
				result := engine.scanTarget(t, lang)
				task.mu.Lock()
				task.Results = append(task.Results, result)
				task.Current++
				task.mu.Unlock()
			}(target)
		}
		wg.Wait()
		task.mu.Lock()
		task.Status = "completed"
		task.mu.Unlock()
	}()

	c.JSON(200, gin.H{"task_id": taskID})
}

func handleTaskStatus(c *gin.Context) {
	taskID := c.Param("id")
	val, ok := tasks.Load(taskID)
	if !ok {
		c.JSON(404, gin.H{"error": "task not found"})
		return
	}
	task := val.(*ScanTask)
	task.mu.Lock()
	defer task.mu.Unlock()
	c.JSON(200, task)
}

func handleTaskSSE(c *gin.Context) {
	taskID := c.Param("id")
	val, ok := tasks.Load(taskID)
	if !ok {
		c.JSON(404, gin.H{"error": "task not found"})
		return
	}
	task := val.(*ScanTask)

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	flusher, _ := c.Writer.(http.Flusher)
	lastSent := 0

	for {
		task.mu.Lock()
		status := task.Status
		current := task.Current
		total := task.Total
		var newResults []ScanResult
		if current > lastSent {
			newResults = make([]ScanResult, len(task.Results[lastSent:current]))
			copy(newResults, task.Results[lastSent:current])
			lastSent = current
		}
		task.mu.Unlock()

		// Send progress
		progressJSON, _ := json.Marshal(gin.H{
			"current": current,
			"total":   total,
			"status":  status,
		})
		fmt.Fprintf(c.Writer, "event: progress\ndata: %s\n\n", progressJSON)

		// Send new results
		for _, r := range newResults {
			resultJSON, _ := json.Marshal(r)
			fmt.Fprintf(c.Writer, "event: result\ndata: %s\n\n", resultJSON)
		}

		if flusher != nil {
			flusher.Flush()
		}

		if status == "completed" || status == "failed" {
			fmt.Fprintf(c.Writer, "event: done\ndata: {}\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			return
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// Knowledge base API - list fingerprints and vulnerabilities
func handleListFingerprints(c *gin.Context) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	type fpInfo struct {
		Name     string            `json:"name"`
		Desc     string            `json:"desc,omitempty"`
		Severity string            `json:"severity"`
		Author   string            `json:"author,omitempty"`
		Metadata map[string]string `json:"metadata,omitempty"`
	}
	fps := make([]fpInfo, 0, len(engine.fps))
	for _, fp := range engine.fps {
		fps = append(fps, fpInfo{
			Name:     fp.Info.Name,
			Desc:     fp.Info.Desc,
			Severity: fp.Info.Severity,
			Author:   fp.Info.Author,
			Metadata: fp.Info.Metadata,
		})
	}
	c.JSON(200, gin.H{"total": len(fps), "items": fps})
}

func handleListVulnerabilities(c *gin.Context) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	name := c.Query("name")
	lang := c.DefaultQuery("lang", "zh")
	advEngine := engine.getAdvEngine(lang)
	all := advEngine.GetAll()
	filtered := make([]vulstruct.Info, 0)
	for _, v := range all {
		if name == "" || v.Info.FingerPrintName == name {
			filtered = append(filtered, v.Info)
		}
	}
	c.JSON(200, gin.H{"total": len(filtered), "items": filtered})
}

// Management API - add fingerprint
func handleAddFingerprint(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "read body failed"})
		return
	}

	// Validate by parsing
	fp, err := parser.InitFingerPrintFromData(body)
	if err != nil {
		c.JSON(400, gin.H{"error": fmt.Sprintf("invalid fingerprint YAML: %v", err)})
		return
	}

	// Save to file
	filename := filepath.Join(engine.fpDir, fp.Info.Name+".yaml")
	if err := os.WriteFile(filename, body, 0644); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("save file: %v", err)})
		return
	}

	// Reload engine
	if err := engine.loadFingerprints(); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("reload: %v", err)})
		return
	}

	c.JSON(200, gin.H{"message": "fingerprint added", "name": fp.Info.Name})
}

// Management API - add vulnerability
func handleAddVulnerability(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(400, gin.H{"error": "read body failed"})
		return
	}

	lang := c.DefaultQuery("lang", "zh")

	// Validate by parsing
	vul, err := vulstruct.ReadVersionVul(body)
	if err != nil {
		c.JSON(400, gin.H{"error": fmt.Sprintf("invalid vulnerability YAML: %v", err)})
		return
	}

	// Determine target directory
	vulBaseDir := engine.vulDir
	if lang == "en" {
		vulBaseDir = engine.vulDirEn
	}

	// Save to file
	vulSubDir := filepath.Join(vulBaseDir, vul.Info.FingerPrintName)
	os.MkdirAll(vulSubDir, 0755)
	filename := filepath.Join(vulSubDir, vul.Info.CVEName+".yaml")
	if err := os.WriteFile(filename, body, 0644); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("save file: %v", err)})
		return
	}

	// Reload
	if err := engine.loadVulnerabilities(); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("reload: %v", err)})
		return
	}

	c.JSON(200, gin.H{"message": "vulnerability added", "cve": vul.Info.CVEName, "component": vul.Info.FingerPrintName})
}

// Management API - delete fingerprint
func handleDeleteFingerprint(c *gin.Context) {
	name := c.Param("name")
	filename := filepath.Join(engine.fpDir, name+".yaml")
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		c.JSON(404, gin.H{"error": "fingerprint not found"})
		return
	}
	if err := os.Remove(filename); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("delete: %v", err)})
		return
	}
	if err := engine.loadFingerprints(); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("reload: %v", err)})
		return
	}
	c.JSON(200, gin.H{"message": "fingerprint deleted"})
}

// Management API - delete vulnerability
func handleDeleteVulnerability(c *gin.Context) {
	name := c.Param("name")
	cve := c.Param("cve")
	// Try both directories
	for _, dir := range []string{engine.vulDir, engine.vulDirEn} {
		filename := filepath.Join(dir, name, cve+".yaml")
		if _, err := os.Stat(filename); err == nil {
			os.Remove(filename)
		}
	}
	if err := engine.loadVulnerabilities(); err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("reload: %v", err)})
		return
	}
	c.JSON(200, gin.H{"message": "vulnerability deleted"})
}

// Summary: components + vul counts
func handleSummary(c *gin.Context) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()

	type componentSummary struct {
		Name     string `json:"name"`
		Desc     string `json:"desc"`
		VulCount int    `json:"vul_count"`
	}

	items := make([]componentSummary, 0)
	for _, fp := range engine.fps {
		ads, _ := engine.advEngineZh.GetAdvisories(fp.Info.Name, "", false)
		items = append(items, componentSummary{
			Name:     fp.Info.Name,
			Desc:     fp.Info.Desc,
			VulCount: len(ads),
		})
	}
	c.JSON(200, gin.H{
		"total_components":      len(engine.fps),
		"total_vulnerabilities": engine.advEngineZh.GetCount(),
		"components":            items,
	})
}

func main() {
	fpDir := getEnv("FP_DIR", "data/fingerprints")
	vulDir := getEnv("VUL_DIR", "data/vuln")
	vulDirEn := getEnv("VUL_DIR_EN", "data/vuln_en")
	listenAddr := getEnv("LISTEN_ADDR", ":8899")
	timeout := 5

	var err error
	engine, err = newScanEngine(fpDir, vulDir, vulDirEn, timeout)
	if err != nil {
		log.Fatalf("Failed to initialize scan engine: %v", err)
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// CORS
	r.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// API routes
	api := r.Group("/api/v1")
	{
		api.POST("/scan", handleScan)
		api.GET("/scan/:id", handleTaskStatus)
		api.GET("/scan/:id/stream", handleTaskSSE)
		api.GET("/summary", handleSummary)
		api.GET("/fingerprints", handleListFingerprints)
		api.GET("/vulnerabilities", handleListVulnerabilities)
		api.POST("/fingerprints", handleAddFingerprint)
		api.DELETE("/fingerprints/:name", handleDeleteFingerprint)
		api.POST("/vulnerabilities", handleAddVulnerability)
		api.DELETE("/vulnerabilities/:name/:cve", handleDeleteVulnerability)
	}

	// Serve icon files from disk (allows runtime additions)
	r.Static("/icons", "static/icons")

	// Serve embedded frontend
	staticSub, _ := fs.Sub(staticFS, "static")
	r.GET("/", func(c *gin.Context) {
		data, err := fs.ReadFile(staticSub, "index.html")
		if err != nil {
			c.String(500, "index.html not found")
			return
		}
		c.Data(200, "text/html; charset=utf-8", data)
	})
	r.GET("/index.html", func(c *gin.Context) {
		c.Redirect(301, "/")
	})
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.FileFromFS("favicon.ico", http.FS(staticSub))
	})

	log.Printf("AIFV-Scanner starting on %s", listenAddr)
	log.Printf("Fingerprints: %s | Vulnerabilities: %s (zh), %s (en)", fpDir, vulDir, vulDirEn)
	if err := r.Run(listenAddr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
