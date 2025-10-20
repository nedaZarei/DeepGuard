package discovery

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// ProjectContext contains detected framework information for a project
type ProjectContext struct {
	// Frameworks maps language names to detected framework names
	// Example: {"javascript": ["express", "prisma"], "python": ["django"]}
	Frameworks map[string][]string
}

// Framework detection keywords for each language
var (
	jsFrameworks = []string{
		"express",
		"prisma",
		"@prisma/client",
		"sequelize",
	}

	pythonFrameworks = []string{
		"django",
		"flask",
		"sqlalchemy",
	}

	javaFrameworks = []string{
		"spring-boot",
		"spring-data-jpa",
		"javax.persistence",
		"jakarta.persistence",
	}
)

// DetectFrameworks analyzes dependency files in the project root to identify frameworks
func DetectFrameworks(rootPath string) (*ProjectContext, error) {
	log.Info().
		Str("component", "discovery").
		Str("operation", "detect_frameworks").
		Str("path", rootPath).
		Msg("Starting framework detection")

	ctx := &ProjectContext{
		Frameworks: make(map[string][]string),
	}

	// Detect JavaScript/TypeScript frameworks
	jsFrameworks, err := detectJSFrameworks(rootPath)
	if err != nil {
		log.Debug().
			Err(err).
			Str("component", "discovery").
			Msg("Error detecting JS frameworks, continuing")
	}
	if len(jsFrameworks) > 0 {
		ctx.Frameworks["javascript"] = jsFrameworks
		ctx.Frameworks["typescript"] = jsFrameworks // Same frameworks for both
	}

	// Detect Python frameworks
	pyFrameworks, err := detectPythonFrameworks(rootPath)
	if err != nil {
		log.Debug().
			Err(err).
			Str("component", "discovery").
			Msg("Error detecting Python frameworks, continuing")
	}
	if len(pyFrameworks) > 0 {
		ctx.Frameworks["python"] = pyFrameworks
	}

	// Detect Java frameworks
	javaFrameworks, err := detectJavaFrameworks(rootPath)
	if err != nil {
		log.Debug().
			Err(err).
			Str("component", "discovery").
			Msg("Error detecting Java frameworks, continuing")
	}
	if len(javaFrameworks) > 0 {
		ctx.Frameworks["java"] = javaFrameworks
	}

	// Log detected frameworks
	for lang, frameworks := range ctx.Frameworks {
		log.Info().
			Str("component", "discovery").
			Str("language", lang).
			Strs("frameworks", frameworks).
			Msg("Detected frameworks")
	}

	return ctx, nil
}

// detectJSFrameworks detects JavaScript/TypeScript frameworks from package.json
func detectJSFrameworks(rootPath string) ([]string, error) {
	packagePath := filepath.Join(rootPath, "package.json")

	// Check if package.json exists
	if _, err := os.Stat(packagePath); os.IsNotExist(err) {
		log.Debug().
			Str("component", "discovery").
			Str("file", "package.json").
			Msg("Dependency file not found")
		return nil, nil
	}

	// Read and parse package.json
	data, err := os.ReadFile(packagePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Collect all dependencies
	allDeps := make(map[string]bool)
	for dep := range pkg.Dependencies {
		allDeps[dep] = true
	}
	for dep := range pkg.DevDependencies {
		allDeps[dep] = true
	}

	// Check for framework keywords (case-sensitive)
	detected := make(map[string]bool)
	for _, framework := range jsFrameworks {
		if allDeps[framework] {
			detected[framework] = true
		}
	}

	// Convert to sorted slice
	result := make([]string, 0, len(detected))
	for fw := range detected {
		result = append(result, fw)
	}

	log.Debug().
		Str("component", "discovery").
		Str("file", "package.json").
		Strs("frameworks", result).
		Msg("Parsed JavaScript frameworks")

	return result, nil
}

// detectPythonFrameworks detects Python frameworks from requirements.txt and setup.py
func detectPythonFrameworks(rootPath string) ([]string, error) {
	detected := make(map[string]bool)

	// Parse requirements.txt
	reqPath := filepath.Join(rootPath, "requirements.txt")
	if _, err := os.Stat(reqPath); err == nil {
		frameworks, err := parseRequirementsTxt(reqPath)
		if err != nil {
			log.Warn().
				Err(err).
				Str("component", "discovery").
				Str("file", "requirements.txt").
				Msg("Failed to parse requirements.txt")
		} else {
			for _, fw := range frameworks {
				detected[fw] = true
			}
		}
	}

	// Parse setup.py
	setupPath := filepath.Join(rootPath, "setup.py")
	if _, err := os.Stat(setupPath); err == nil {
		frameworks, err := parseSetupPy(setupPath)
		if err != nil {
			log.Warn().
				Err(err).
				Str("component", "discovery").
				Str("file", "setup.py").
				Msg("Failed to parse setup.py")
		} else {
			for _, fw := range frameworks {
				detected[fw] = true
			}
		}
	}

	// Convert to slice
	result := make([]string, 0, len(detected))
	for fw := range detected {
		result = append(result, fw)
	}

	log.Debug().
		Str("component", "discovery").
		Strs("frameworks", result).
		Msg("Parsed Python frameworks")

	return result, nil
}

// parseRequirementsTxt parses requirements.txt file
func parseRequirementsTxt(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	detected := make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract package name (before ==, >=, <=, etc.)
		// Also handle package[extras]==version
		packageName := line
		for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "[", " "} {
			if idx := strings.Index(packageName, sep); idx != -1 {
				packageName = packageName[:idx]
				break
			}
		}

		packageName = strings.TrimSpace(packageName)

		// Check against framework list (case-insensitive for Python)
		packageLower := strings.ToLower(packageName)
		for _, framework := range pythonFrameworks {
			if packageLower == strings.ToLower(framework) {
				detected[strings.ToLower(framework)] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(detected))
	for fw := range detected {
		result = append(result, fw)
	}

	return result, nil
}

// parseSetupPy parses setup.py to extract install_requires
func parseSetupPy(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	detected := make(map[string]bool)

	// Regex to find install_requires list (with DOTALL to match newlines)
	// Matches: install_requires=['package1', 'package2', ...]
	// or: install_requires=["package1", "package2", ...]
	re := regexp.MustCompile(`(?s)install_requires\s*=\s*\[(.*?)\]`)
	matches := re.FindStringSubmatch(content)

	if len(matches) > 1 {
		// Extract package names from the list
		requiresStr := matches[1]

		// Find all quoted strings
		packageRe := regexp.MustCompile(`['"]([^'"]+)['"]`)
		packages := packageRe.FindAllStringSubmatch(requiresStr, -1)

		for _, pkg := range packages {
			if len(pkg) > 1 {
				packageName := pkg[1]

				// Extract package name (before version specifiers)
				for _, sep := range []string{"==", ">=", "<=", "~=", "!=", ">", "<", "["} {
					if idx := strings.Index(packageName, sep); idx != -1 {
						packageName = packageName[:idx]
						break
					}
				}

				packageName = strings.TrimSpace(packageName)
				packageLower := strings.ToLower(packageName)

				// Check against framework list
				for _, framework := range pythonFrameworks {
					if packageLower == strings.ToLower(framework) {
						detected[strings.ToLower(framework)] = true
					}
				}
			}
		}
	}

	result := make([]string, 0, len(detected))
	for fw := range detected {
		result = append(result, fw)
	}

	return result, nil
}

// detectJavaFrameworks detects Java frameworks from pom.xml and build.gradle
func detectJavaFrameworks(rootPath string) ([]string, error) {
	detected := make(map[string]bool)

	// Parse pom.xml
	pomPath := filepath.Join(rootPath, "pom.xml")
	if _, err := os.Stat(pomPath); err == nil {
		frameworks, err := parsePomXml(pomPath)
		if err != nil {
			log.Warn().
				Err(err).
				Str("component", "discovery").
				Str("file", "pom.xml").
				Msg("Failed to parse pom.xml")
		} else {
			for _, fw := range frameworks {
				detected[fw] = true
			}
		}
	}

	// Parse build.gradle
	gradlePath := filepath.Join(rootPath, "build.gradle")
	if _, err := os.Stat(gradlePath); err == nil {
		frameworks, err := parseBuildGradle(gradlePath)
		if err != nil {
			log.Warn().
				Err(err).
				Str("component", "discovery").
				Str("file", "build.gradle").
				Msg("Failed to parse build.gradle")
		} else {
			for _, fw := range frameworks {
				detected[fw] = true
			}
		}
	}

	result := make([]string, 0, len(detected))
	for fw := range detected {
		result = append(result, fw)
	}

	log.Debug().
		Str("component", "discovery").
		Strs("frameworks", result).
		Msg("Parsed Java frameworks")

	return result, nil
}

// parsePomXml parses pom.xml to extract dependencies
func parsePomXml(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Define XML structure for parsing
	type Dependency struct {
		GroupId    string `xml:"groupId"`
		ArtifactId string `xml:"artifactId"`
	}

	type Dependencies struct {
		Dependency []Dependency `xml:"dependency"`
	}

	type Project struct {
		Dependencies Dependencies `xml:"dependencies"`
	}

	var project Project
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, fmt.Errorf("failed to parse pom.xml: %w", err)
	}

	detected := make(map[string]bool)

	// Check artifactId and groupId for framework keywords
	for _, dep := range project.Dependencies.Dependency {
		artifactId := strings.ToLower(dep.ArtifactId)
		groupId := strings.ToLower(dep.GroupId)
		combined := artifactId + " " + groupId

		for _, framework := range javaFrameworks {
			frameworkLower := strings.ToLower(framework)

			// Special handling for compound framework names
			if frameworkLower == "spring-data-jpa" {
				// Match "data-jpa" or "spring-data-jpa"
				if strings.Contains(combined, "data-jpa") || strings.Contains(combined, "spring-data-jpa") {
					detected[framework] = true
				}
			} else if strings.Contains(combined, frameworkLower) {
				detected[framework] = true
			}
		}
	}

	result := make([]string, 0, len(detected))
	for fw := range detected {
		result = append(result, fw)
	}

	return result, nil
}

// parseBuildGradle parses build.gradle to extract dependencies
func parseBuildGradle(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(data)
	detected := make(map[string]bool)

	// Regex to find dependency declarations
	// Matches: implementation 'group:artifact:version'
	// or: compile 'group:artifact:version'
	re := regexp.MustCompile(`(?:implementation|compile|api|runtimeOnly)\s+['"]([^'"]+)['"]`)
	matches := re.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			dependency := match[1]

			// Check if dependency contains framework keywords
			depLower := strings.ToLower(dependency)
			for _, framework := range javaFrameworks {
				frameworkLower := strings.ToLower(framework)
				if strings.Contains(depLower, frameworkLower) {
					detected[framework] = true
				}
			}
		}
	}

	result := make([]string, 0, len(detected))
	for fw := range detected {
		result = append(result, fw)
	}

	return result, nil
}
