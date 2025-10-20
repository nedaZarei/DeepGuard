package discovery

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// setupFrameworkTest creates a test directory with sample dependency files
func setupFrameworkTest(t *testing.T, files map[string]string) string {
	tmpDir := t.TempDir()

	for filename, content := range files {
		path := filepath.Join(tmpDir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file %s: %v", filename, err)
		}
	}

	return tmpDir
}

func TestDetectJSFrameworks_Express(t *testing.T) {
	packageJSON := `{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "body-parser": "^1.20.0"
  }
}`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"package.json": packageJSON,
	})

	frameworks, err := detectJSFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectJSFrameworks failed: %v", err)
	}

	if len(frameworks) != 1 {
		t.Errorf("Expected 1 framework, got %d: %v", len(frameworks), frameworks)
	}

	if len(frameworks) > 0 && frameworks[0] != "express" {
		t.Errorf("Expected 'express', got '%s'", frameworks[0])
	}
}

func TestDetectJSFrameworks_MultiplePrisma(t *testing.T) {
	packageJSON := `{
  "name": "my-app",
  "dependencies": {
    "express": "^4.18.0",
    "@prisma/client": "^5.0.0"
  },
  "devDependencies": {
    "prisma": "^5.0.0"
  }
}`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"package.json": packageJSON,
	})

	frameworks, err := detectJSFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectJSFrameworks failed: %v", err)
	}

	// Should detect express, @prisma/client, and prisma
	if len(frameworks) < 2 {
		t.Errorf("Expected at least 2 frameworks, got %d: %v", len(frameworks), frameworks)
	}

	hasExpress := false
	hasPrisma := false
	for _, fw := range frameworks {
		if fw == "express" {
			hasExpress = true
		}
		if fw == "@prisma/client" || fw == "prisma" {
			hasPrisma = true
		}
	}

	if !hasExpress {
		t.Error("Expected to find 'express'")
	}
	if !hasPrisma {
		t.Error("Expected to find prisma framework")
	}
}

func TestDetectJSFrameworks_NoPackageJSON(t *testing.T) {
	tmpDir := t.TempDir()

	frameworks, err := detectJSFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectJSFrameworks failed: %v", err)
	}

	if len(frameworks) != 0 {
		t.Errorf("Expected 0 frameworks for missing package.json, got %d", len(frameworks))
	}
}

func TestDetectJSFrameworks_InvalidJSON(t *testing.T) {
	tmpDir := setupFrameworkTest(t, map[string]string{
		"package.json": `{ invalid json`,
	})

	_, err := detectJSFrameworks(tmpDir)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestDetectPythonFrameworks_RequirementsTxt(t *testing.T) {
	requirementsTxt := `# Python dependencies
Django==4.2.0
requests>=2.28.0
psycopg2-binary==2.9.5
`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"requirements.txt": requirementsTxt,
	})

	frameworks, err := detectPythonFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectPythonFrameworks failed: %v", err)
	}

	if len(frameworks) != 1 {
		t.Errorf("Expected 1 framework, got %d: %v", len(frameworks), frameworks)
	}

	if len(frameworks) > 0 && frameworks[0] != "django" {
		t.Errorf("Expected 'django', got '%s'", frameworks[0])
	}
}

func TestDetectPythonFrameworks_CaseInsensitive(t *testing.T) {
	requirementsTxt := `Django==4.2.0
Flask==2.3.0
SQLAlchemy>=2.0.0
`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"requirements.txt": requirementsTxt,
	})

	frameworks, err := detectPythonFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectPythonFrameworks failed: %v", err)
	}

	if len(frameworks) != 3 {
		t.Errorf("Expected 3 frameworks, got %d: %v", len(frameworks), frameworks)
	}

	// All should be lowercase
	for _, fw := range frameworks {
		if fw != strings.ToLower(fw) {
			t.Errorf("Expected lowercase framework name, got '%s'", fw)
		}
	}
}

func TestDetectPythonFrameworks_SetupPy(t *testing.T) {
	setupPy := `from setuptools import setup, find_packages

setup(
    name='my-app',
    version='1.0.0',
    packages=find_packages(),
    install_requires=[
        'Django>=4.0',
        'djangorestframework',
        'sqlalchemy',
    ],
)`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"setup.py": setupPy,
	})

	frameworks, err := detectPythonFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectPythonFrameworks failed: %v", err)
	}

	// Should detect django and sqlalchemy
	if len(frameworks) < 2 {
		t.Errorf("Expected at least 2 frameworks, got %d: %v", len(frameworks), frameworks)
	}

	hasDjango := false
	hasSQLAlchemy := false
	for _, fw := range frameworks {
		if fw == "django" {
			hasDjango = true
		}
		if fw == "sqlalchemy" {
			hasSQLAlchemy = true
		}
	}

	if !hasDjango {
		t.Error("Expected to find 'django'")
	}
	if !hasSQLAlchemy {
		t.Error("Expected to find 'sqlalchemy'")
	}
}

func TestDetectPythonFrameworks_BothFiles(t *testing.T) {
	requirementsTxt := `Flask==2.3.0`
	setupPy := `setup(install_requires=['Django>=4.0'])`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"requirements.txt": requirementsTxt,
		"setup.py":         setupPy,
	})

	frameworks, err := detectPythonFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectPythonFrameworks failed: %v", err)
	}

	// Should detect both flask and django
	if len(frameworks) != 2 {
		t.Errorf("Expected 2 frameworks, got %d: %v", len(frameworks), frameworks)
	}
}

func TestDetectJavaFrameworks_PomXml(t *testing.T) {
	pomXml := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>my-app</artifactId>
    <version>1.0.0</version>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.0.0</version>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
            <version>3.0.0</version>
        </dependency>
    </dependencies>
</project>`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"pom.xml": pomXml,
	})

	frameworks, err := detectJavaFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectJavaFrameworks failed: %v", err)
	}

	// Should detect spring-boot and spring-data-jpa
	if len(frameworks) < 2 {
		t.Errorf("Expected at least 2 frameworks, got %d: %v", len(frameworks), frameworks)
	}

	hasSpringBoot := false
	hasSpringDataJPA := false
	for _, fw := range frameworks {
		if fw == "spring-boot" {
			hasSpringBoot = true
		}
		if fw == "spring-data-jpa" {
			hasSpringDataJPA = true
		}
	}

	if !hasSpringBoot {
		t.Error("Expected to find 'spring-boot'")
	}
	if !hasSpringDataJPA {
		t.Error("Expected to find 'spring-data-jpa'")
	}
}

func TestDetectJavaFrameworks_BuildGradle(t *testing.T) {
	buildGradle := `plugins {
    id 'java'
    id 'org.springframework.boot' version '3.0.0'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    compile 'javax.persistence:javax.persistence-api:2.2'
}`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"build.gradle": buildGradle,
	})

	frameworks, err := detectJavaFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("detectJavaFrameworks failed: %v", err)
	}

	// Should detect spring-boot, spring-data-jpa, and javax.persistence
	if len(frameworks) < 2 {
		t.Errorf("Expected at least 2 frameworks, got %d: %v", len(frameworks), frameworks)
	}

	hasSpringBoot := false
	hasPersistence := false
	for _, fw := range frameworks {
		if fw == "spring-boot" {
			hasSpringBoot = true
		}
		if fw == "javax.persistence" || fw == "spring-data-jpa" {
			hasPersistence = true
		}
	}

	if !hasSpringBoot {
		t.Error("Expected to find 'spring-boot'")
	}
	if !hasPersistence {
		t.Error("Expected to find persistence framework")
	}
}

func TestDetectFrameworks_MultiLanguage(t *testing.T) {
	packageJSON := `{"dependencies": {"express": "^4.18.0"}}`
	requirementsTxt := `Django==4.2.0`
	pomXml := `<?xml version="1.0"?>
<project><dependencies>
<dependency><artifactId>spring-boot-starter</artifactId></dependency>
</dependencies></project>`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"package.json":     packageJSON,
		"requirements.txt": requirementsTxt,
		"pom.xml":          pomXml,
	})

	ctx, err := DetectFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("DetectFrameworks failed: %v", err)
	}

	// Should detect frameworks for all three languages
	if len(ctx.Frameworks) < 3 {
		t.Errorf("Expected frameworks for 3 languages, got %d", len(ctx.Frameworks))
	}

	// Check JavaScript/TypeScript
	if jsFrameworks, ok := ctx.Frameworks["javascript"]; !ok || len(jsFrameworks) == 0 {
		t.Error("Expected JavaScript frameworks")
	}
	if tsFrameworks, ok := ctx.Frameworks["typescript"]; !ok || len(tsFrameworks) == 0 {
		t.Error("Expected TypeScript frameworks (same as JavaScript)")
	}

	// Check Python
	if pyFrameworks, ok := ctx.Frameworks["python"]; !ok || len(pyFrameworks) == 0 {
		t.Error("Expected Python frameworks")
	}

	// Check Java
	if javaFrameworks, ok := ctx.Frameworks["java"]; !ok || len(javaFrameworks) == 0 {
		t.Error("Expected Java frameworks")
	}
}

func TestDetectFrameworks_NoFiles(t *testing.T) {
	tmpDir := t.TempDir()

	ctx, err := DetectFrameworks(tmpDir)
	if err != nil {
		t.Fatalf("DetectFrameworks failed: %v", err)
	}

	if len(ctx.Frameworks) != 0 {
		t.Errorf("Expected no frameworks, got %d languages", len(ctx.Frameworks))
	}
}

func TestParseRequirementsTxt_VersionSpecifiers(t *testing.T) {
	requirementsTxt := `Django==4.2.0
Flask>=2.0.0
sqlalchemy~=2.0
requests<=2.28.0
# Comment line
pytest>=7.0  # Inline comment
`

	tmpDir := setupFrameworkTest(t, map[string]string{
		"requirements.txt": requirementsTxt,
	})

	path := filepath.Join(tmpDir, "requirements.txt")
	frameworks, err := parseRequirementsTxt(path)
	if err != nil {
		t.Fatalf("parseRequirementsTxt failed: %v", err)
	}

	// Should find django, flask, and sqlalchemy
	if len(frameworks) != 3 {
		t.Errorf("Expected 3 frameworks, got %d: %v", len(frameworks), frameworks)
	}

	sort.Strings(frameworks)
	expected := []string{"django", "flask", "sqlalchemy"}
	sort.Strings(expected)

	for i, fw := range frameworks {
		if fw != expected[i] {
			t.Errorf("Expected '%s' at position %d, got '%s'", expected[i], i, fw)
		}
	}
}

func TestParsePomXml_InvalidXML(t *testing.T) {
	tmpDir := setupFrameworkTest(t, map[string]string{
		"pom.xml": `<invalid xml`,
	})

	path := filepath.Join(tmpDir, "pom.xml")
	_, err := parsePomXml(path)
	if err == nil {
		t.Error("Expected error for invalid XML")
	}
}
