package llm

// FrameworkHints provides vulnerability-specific guidance for detected frameworks
type FrameworkHints struct {
	// Framework name (e.g., "express", "django", "spring")
	Framework string
	// Vulnerability-specific hints mapped by vulnerability type
	Hints map[VulnerabilityType]string
}

// VulnerabilityType represents different categories of security vulnerabilities
type VulnerabilityType string

const (
	VulnTypeSQLInjection            VulnerabilityType = "sql_injection"
	VulnTypeXSS                     VulnerabilityType = "xss"
	VulnTypePathTraversal           VulnerabilityType = "path_traversal"
	VulnTypeInsecureDeserialization VulnerabilityType = "insecure_deserialization"
	VulnTypeAuthIssue               VulnerabilityType = "auth_issue"
	VulnTypeCryptoIssue             VulnerabilityType = "crypto_issue"
	VulnTypeCommandInjection        VulnerabilityType = "command_injection"
	VulnTypeSSRF                    VulnerabilityType = "ssrf"
)

// frameworkHintsMap contains framework-specific guidance for each vulnerability type
var frameworkHintsMap = map[string]FrameworkHints{
	"express": {
		Framework: "express",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Check req.query, req.params, req.body for unsanitized input in SQL queries. Look for string concatenation or template literals in database queries.",
			VulnTypeXSS:                     "Check res.send(), res.write() with unsanitized user input. Look for template rendering without proper escaping (e.g., EJS without <%= %>).",
			VulnTypePathTraversal:           "Check fs.readFile(), fs.readFileSync(), path.join() with req.query or req.params. Look for missing path.normalize() or path.resolve() validation.",
			VulnTypeInsecureDeserialization: "Check JSON.parse() with untrusted input, especially with reviver functions. Look for eval() or Function() constructor usage.",
			VulnTypeAuthIssue:               "Check JWT verification (jwt.verify without secret validation), session middleware configuration, missing authentication middleware on protected routes.",
			VulnTypeCryptoIssue:             "Check crypto.createHash() for weak algorithms (MD5, SHA1), hardcoded secrets in crypto operations, insecure random number generation.",
			VulnTypeCommandInjection:        "Check child_process.exec(), execSync(), spawn() with req.query/req.params/req.body. Unsafe: exec('ping ' + req.query.host). Safe: execFile('ping', ['-c','1', validatedHost]).",
			VulnTypeSSRF:                    "Check fetch(), axios.get(), http.request(), got() called with URLs from req.query, req.params, or req.body. Validate URL host against an allowlist before making the request.",
		},
	},
	"prisma": {
		Framework: "prisma",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Focus on prisma.$queryRaw and prisma.$executeRaw with template literals. Check for unsanitized variables in raw queries. Safe: prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`. Unsafe: prisma.$queryRaw(`SELECT * FROM users WHERE id = ${userId}`).",
			VulnTypeXSS:                     "Prisma handles database operations, but check data returned to views. Ensure proper escaping when rendering Prisma query results in templates.",
			VulnTypePathTraversal:           "Not applicable to Prisma ORM.",
			VulnTypeInsecureDeserialization: "Check JSON field handling, especially when using Json type with untrusted input.",
			VulnTypeAuthIssue:               "Check row-level security implementation, missing where clauses for user-specific data access.",
			VulnTypeCryptoIssue:             "Check password hashing before prisma.user.create(). Ensure bcrypt/argon2 usage, not plain text or weak hashing.",
		},
	},
	"sequelize": {
		Framework: "sequelize",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Check sequelize.query() with raw SQL and string concatenation. Look for missing replacements parameter or using bind instead of replacements. Safe: sequelize.query('SELECT * FROM users WHERE id = :id', { replacements: { id } }). Unsafe: sequelize.query(`SELECT * FROM users WHERE id = ${id}`).",
			VulnTypeXSS:                     "Check data returned from queries when rendered in views. Ensure proper escaping in templates.",
			VulnTypePathTraversal:           "Not applicable to Sequelize ORM.",
			VulnTypeInsecureDeserialization: "Check JSON/JSONB field handling with untrusted input.",
			VulnTypeAuthIssue:               "Check model scopes for user isolation, missing where clauses for user-specific queries.",
			VulnTypeCryptoIssue:             "Check password hashing in hooks (beforeCreate, beforeUpdate). Ensure bcrypt usage.",
		},
	},
	"django": {
		Framework: "django",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Check django.db.connection.cursor() with raw SQL, .raw() method, .extra() with unsafe parameters. Look for string formatting in queries. Safe: cursor.execute('SELECT * FROM users WHERE id = %s', [user_id]). Unsafe: cursor.execute(f'SELECT * FROM users WHERE id = {user_id}').",
			VulnTypeXSS:                     "Check {% autoescape off %}, mark_safe() usage, |safe filter in templates. Look for render() with user input not properly escaped.",
			VulnTypePathTraversal:           "Check open(), File(), FileResponse() with user input. Look for missing os.path.abspath() or os.path.normpath() validation.",
			VulnTypeInsecureDeserialization: "Check pickle.loads(), yaml.load() without SafeLoader, eval() usage.",
			VulnTypeAuthIssue:               "Check @login_required decorator usage, permission_required, missing authentication on views, improper session configuration.",
			VulnTypeCryptoIssue:             "Check make_password() usage, SECRET_KEY configuration, use of MD5/SHA1 for passwords.",
			VulnTypeCommandInjection:        "Check os.system(), os.popen(), subprocess.call/run/Popen() with request.GET/POST values. Unsafe: subprocess.call(cmd, shell=True) with user input. Safe: subprocess.run(['ping', '-c', '1', validated_host], shell=False).",
			VulnTypeSSRF:                    "Check requests.get/post(), urllib.request.urlopen() called with request.GET/POST values as the URL. Validate URL scheme and host against an allowlist before fetching.",
		},
	},
	"flask": {
		Framework: "flask",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Check db.execute(), db.session.execute() with string formatting. Look for f-strings or % formatting in SQL queries.",
			VulnTypeXSS:                     "Check Markup() or |safe filter in Jinja2 templates, render_template_string() with user input. Ensure autoescape is enabled.",
			VulnTypePathTraversal:           "Check send_file(), send_from_directory() with request.args or request.form. Look for missing secure_filename() usage.",
			VulnTypeInsecureDeserialization: "Check pickle.loads(), yaml.load(), eval() with flask.request data.",
			VulnTypeAuthIssue:               "Check @login_required usage, session configuration (SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY), JWT verification.",
			VulnTypeCryptoIssue:             "Check SECRET_KEY configuration, werkzeug.security functions, use of MD5/SHA1.",
			VulnTypeCommandInjection:        "Check os.system(), os.popen(), subprocess.call/run() with request.args/form values. Unsafe: os.popen('curl ' + request.args.get('url')). Safe: subprocess.run(['curl', validated_url], shell=False).",
			VulnTypeSSRF:                    "Check requests.get/post(), urllib.request.urlopen(), httpx.get() called with request.args/form values as the URL. Validate URL against allowlist of permitted hosts.",
		},
	},
	"sqlalchemy": {
		Framework: "sqlalchemy",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Check text() with string formatting, execute() with raw SQL strings. Look for f-strings or .format() in queries. Safe: session.execute(text('SELECT * FROM users WHERE id = :id'), {'id': user_id}). Unsafe: session.execute(text(f'SELECT * FROM users WHERE id = {user_id}')).",
			VulnTypeXSS:                     "SQLAlchemy handles database operations. Check data returned to views for proper escaping.",
			VulnTypePathTraversal:           "Not applicable to SQLAlchemy ORM.",
			VulnTypeInsecureDeserialization: "Check JSON column handling with untrusted input.",
			VulnTypeAuthIssue:               "Check query filters for user isolation, missing user context in queries.",
			VulnTypeCryptoIssue:             "Check password hashing before insert/update. Ensure bcrypt/argon2 usage.",
		},
	},
	"spring": {
		Framework: "spring",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Check @Query annotations with string concatenation, JdbcTemplate.query() with string formatting. Look for + operator in JPQL/HQL queries. Safe: jdbcTemplate.query('SELECT * FROM users WHERE id = ?', new Object[]{id}). Unsafe: jdbcTemplate.query('SELECT * FROM users WHERE id = ' + id).",
			VulnTypeXSS:                     "Check @ResponseBody without proper escaping, Thymeleaf th:utext attribute, ResponseEntity with unsanitized content.",
			VulnTypePathTraversal:           "Check FileInputStream, FileReader, Paths.get() with @RequestParam or @PathVariable. Look for missing path validation.",
			VulnTypeInsecureDeserialization: "Check ObjectInputStream usage, @RequestBody with untrusted JSON, XStream configuration.",
			VulnTypeAuthIssue:               "Check @PreAuthorize, @Secured annotations, SecurityContext usage, JWT validation in filters.",
			VulnTypeCryptoIssue:             "Check PasswordEncoder configuration (ensure BCryptPasswordEncoder), MessageDigest for weak algorithms, hardcoded keys.",
			VulnTypeCommandInjection:        "Check Runtime.getRuntime().exec() and ProcessBuilder with @RequestParam or @PathVariable values. Safe: new ProcessBuilder('ping', '-c', '1', validatedHost).start(). Unsafe: Runtime.getRuntime().exec('ping ' + host).",
			VulnTypeSSRF:                    "Check RestTemplate.getForObject/postForObject(), WebClient.get().uri(), HttpClient with URLs derived from @RequestParam or @RequestBody. Validate URL against allowlist before fetching.",
		},
	},
	"jpa": {
		Framework: "jpa",
		Hints: map[VulnerabilityType]string{
			VulnTypeSQLInjection:            "Check createNativeQuery() with string concatenation, JPQL queries with string formatting. Look for + operator in queries. Safe: em.createNativeQuery('SELECT * FROM users WHERE id = ?1').setParameter(1, id). Unsafe: em.createNativeQuery('SELECT * FROM users WHERE id = ' + id).",
			VulnTypeXSS:                     "JPA handles database operations. Check data returned to views for proper escaping.",
			VulnTypePathTraversal:           "Not applicable to JPA.",
			VulnTypeInsecureDeserialization: "Check @Lob fields with untrusted binary data.",
			VulnTypeAuthIssue:               "Check @PreAuthorize on repository methods, missing user filtering in queries.",
			VulnTypeCryptoIssue:             "Check password hashing in entity lifecycle hooks. Ensure BCrypt usage.",
			VulnTypeCommandInjection:        "Not commonly applicable to JPA. Check any service methods that invoke OS commands alongside database operations.",
			VulnTypeSSRF:                    "JPA handles database operations. Check any service methods that make HTTP calls with data loaded from the database or user input.",
		},
	},
}

// GetFrameworkHints returns vulnerability-specific hints for a framework
func GetFrameworkHints(framework string, vulnType VulnerabilityType) string {
	if hints, ok := frameworkHintsMap[framework]; ok {
		if hint, ok := hints.Hints[vulnType]; ok {
			return hint
		}
	}
	return ""
}

// GetAllFrameworkHints returns all hints for multiple frameworks for a specific vulnerability type
func GetAllFrameworkHints(frameworks []string, vulnType VulnerabilityType) []string {
	var hints []string
	seen := make(map[string]bool)

	for _, framework := range frameworks {
		hint := GetFrameworkHints(framework, vulnType)
		if hint != "" && !seen[hint] {
			hints = append(hints, hint)
			seen[hint] = true
		}
	}

	return hints
}
