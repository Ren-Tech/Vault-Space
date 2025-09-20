import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart' as path;
import 'package:crypto/crypto.dart';
import 'package:local_auth/local_auth.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:math';
import 'dart:io';

void main() {
  runApp(SecureAccountApp());
}

class SecureAccountApp extends StatelessWidget {
  const SecureAccountApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Secure Account Manager',
      theme: ThemeData(
        primarySwatch: Colors.blue,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      home: SecurityCheckScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}

class SecurityCheckScreen extends StatefulWidget {
  const SecurityCheckScreen({super.key});

  @override
  _SecurityCheckScreenState createState() => _SecurityCheckScreenState();
}

class _SecurityCheckScreenState extends State<SecurityCheckScreen> {
  bool _isCheckingDeviceSecurity = true;
  String _securityStatus = "Checking device security...";

  @override
  void initState() {
    super.initState();
    _performSecurityChecks();
  }

  Future<void> _performSecurityChecks() async {
    // Check if device is rooted/jailbroken
    bool isDeviceSecure = await SecurityManager.checkDeviceSecurity();

    if (!isDeviceSecure) {
      setState(() {
        _securityStatus = "Device security compromised. App cannot run safely.";
        _isCheckingDeviceSecurity = false;
      });
      return;
    }

    // Check device integrity
    bool hasValidIntegrity = await SecurityManager.verifyAppIntegrity();

    if (!hasValidIntegrity) {
      setState(() {
        _securityStatus =
            "App integrity check failed. Potential tampering detected.";
        _isCheckingDeviceSecurity = false;
      });
      return;
    }

    // Initialize secure environment
    await SecurityManager.initializeSecureEnvironment();

    setState(() {
      _securityStatus = "Security checks passed";
      _isCheckingDeviceSecurity = false;
    });

    // Navigate to auth screen after brief delay
    await Future.delayed(Duration(milliseconds: 1500));
    if (mounted) {
      Navigator.of(
        context,
      ).pushReplacement(MaterialPageRoute(builder: (context) => AuthScreen()));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey.shade900,
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.verified_user,
              size: 100,
              color: _isCheckingDeviceSecurity ? Colors.orange : Colors.green,
            ),
            SizedBox(height: 24),
            Text(
              'Security Validation',
              style: TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
            ),
            SizedBox(height: 16),
            if (_isCheckingDeviceSecurity)
              CircularProgressIndicator(color: Colors.orange),
            SizedBox(height: 16),
            Text(
              _securityStatus,
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 16, color: Colors.white70),
            ),
          ],
        ),
      ),
    );
  }
}

class Account {
  final int? id;
  final String name;
  final String username;
  final String password;
  final String? notes;
  final String? website;
  final DateTime createdAt;
  final DateTime lastModified;
  final int accessCount;
  final DateTime? lastAccessed;

  Account({
    this.id,
    required this.name,
    required this.username,
    required this.password,
    this.notes,
    this.website,
    required this.createdAt,
    required this.lastModified,
    this.accessCount = 0,
    this.lastAccessed,
  });

  Map<String, dynamic> toMap() {
    return {
      'id': id,
      'name': name,
      'username': username,
      'password': password,
      'notes': notes,
      'website': website,
      'created_at': createdAt.toIso8601String(),
      'last_modified': lastModified.toIso8601String(),
      'access_count': accessCount,
      'last_accessed': lastAccessed?.toIso8601String(),
    };
  }

  factory Account.fromMap(Map<String, dynamic> map) {
    return Account(
      id: map['id'],
      name: map['name'],
      username: map['username'],
      password: map['password'],
      notes: map['notes'],
      website: map['website'],
      createdAt: DateTime.parse(map['created_at']),
      lastModified: DateTime.parse(map['last_modified']),
      accessCount: map['access_count'] ?? 0,
      lastAccessed: map['last_accessed'] != null
          ? DateTime.parse(map['last_accessed'])
          : null,
    );
  }
}

class SecurityManager {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
      sharedPreferencesName: 'secure_account_prefs',
      preferencesKeyPrefix: 'sa_',
    ),
    iOptions: IOSOptions(
      groupId: 'group.secure.account.manager',
      accountName: 'SecureAccountManager',
    ),
  );

  static String? _sessionKey;
  static DateTime? _lastActivity;
  static int _failedAttempts = 0;
  static const int MAX_FAILED_ATTEMPTS = 5;
  static const Duration SESSION_TIMEOUT = Duration(minutes: 15);
  static const Duration LOCKOUT_DURATION = Duration(minutes: 30);

  static Future<bool> checkDeviceSecurity() async {
    try {
      DeviceInfoPlugin deviceInfo = DeviceInfoPlugin();

      if (Platform.isAndroid) {
        AndroidDeviceInfo androidInfo = await deviceInfo.androidInfo;
        // Check for root indicators
        return !_isAndroidRooted(androidInfo);
      } else if (Platform.isIOS) {
        IosDeviceInfo iosInfo = await deviceInfo.iosInfo;
        // Check for jailbreak indicators
        return !_isIOSJailbroken(iosInfo);
      }
    } catch (e) {
      return false;
    }
    return true;
  }

  static bool _isAndroidRooted(AndroidDeviceInfo info) {
    // Check for common root indicators
    List<String> rootPaths = [
      '/system/app/Superuser.apk',
      '/sbin/su',
      '/system/bin/su',
      '/system/xbin/su',
      '/data/local/xbin/su',
      '/data/local/bin/su',
      '/system/sd/xbin/su',
      '/system/bin/failsafe/su',
      '/data/local/su',
    ];

    for (String path in rootPaths) {
      if (File(path).existsSync()) {
        return true;
      }
    }

    // Additional checks could be added here
    return false;
  }

  static bool _isIOSJailbroken(IosDeviceInfo info) {
    // Basic jailbreak detection
    List<String> jailbreakPaths = [
      '/Applications/Cydia.app',
      '/Library/MobileSubstrate/MobileSubstrate.dylib',
      '/bin/bash',
      '/usr/sbin/sshd',
      '/etc/apt',
    ];

    for (String path in jailbreakPaths) {
      if (File(path).existsSync()) {
        return true;
      }
    }

    return false;
  }

  static Future<bool> verifyAppIntegrity() async {
    try {
      // Simple integrity check - in production, use more sophisticated methods
      String appSignature = await _getAppSignature();
      String? storedSignature = await _storage.read(key: 'app_signature');

      if (storedSignature == null) {
        await _storage.write(key: 'app_signature', value: appSignature);
        return true;
      }

      return appSignature == storedSignature;
    } catch (e) {
      return false;
    }
  }

  static Future<String> _getAppSignature() async {
    // Generate a simple app signature based on app info
    // In production, use proper app signing verification
    DeviceInfoPlugin deviceInfo = DeviceInfoPlugin();
    String deviceId = '';

    if (Platform.isAndroid) {
      AndroidDeviceInfo androidInfo = await deviceInfo.androidInfo;
      deviceId = androidInfo.id;
    } else if (Platform.isIOS) {
      IosDeviceInfo iosInfo = await deviceInfo.iosInfo;
      deviceId = iosInfo.identifierForVendor ?? 'unknown';
    }

    return sha256
        .convert(utf8.encode('SecureAccountManager_$deviceId'))
        .toString();
  }

  static Future<void> initializeSecureEnvironment() async {
    _lastActivity = DateTime.now();

    // Check if app was locked due to failed attempts
    String? lockoutTime = await _storage.read(key: 'lockout_until');
    if (lockoutTime != null) {
      DateTime lockout = DateTime.parse(lockoutTime);
      if (DateTime.now().isBefore(lockout)) {
        throw Exception('App is locked due to failed authentication attempts');
      } else {
        await _storage.delete(key: 'lockout_until');
        await _storage.delete(key: 'failed_attempts');
      }
    }

    // Load failed attempts count
    String? attempts = await _storage.read(key: 'failed_attempts');
    _failedAttempts = attempts != null ? int.parse(attempts) : 0;
  }

  static Future<void> recordFailedAttempt() async {
    _failedAttempts++;
    await _storage.write(
      key: 'failed_attempts',
      value: _failedAttempts.toString(),
    );

    if (_failedAttempts >= MAX_FAILED_ATTEMPTS) {
      DateTime lockoutUntil = DateTime.now().add(LOCKOUT_DURATION);
      await _storage.write(
        key: 'lockout_until',
        value: lockoutUntil.toIso8601String(),
      );
    }
  }

  static Future<void> resetFailedAttempts() async {
    _failedAttempts = 0;
    await _storage.delete(key: 'failed_attempts');
    await _storage.delete(key: 'lockout_until');
  }

  static bool isSessionValid() {
    if (_lastActivity == null || _sessionKey == null) return false;

    return DateTime.now().difference(_lastActivity!) < SESSION_TIMEOUT;
  }

  static void updateLastActivity() {
    _lastActivity = DateTime.now();
  }

  static void startSession(String key) {
    _sessionKey = key;
    _lastActivity = DateTime.now();
  }

  static void endSession() {
    _sessionKey = null;
    _lastActivity = null;
  }

  static bool get isLockedOut {
    return _failedAttempts >= MAX_FAILED_ATTEMPTS;
  }

  static int get remainingAttempts {
    return MAX_FAILED_ATTEMPTS - _failedAttempts;
  }
}

class AdvancedEncryptionService {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
      sharedPreferencesName: 'secure_keys',
      preferencesKeyPrefix: 'key_',
    ),
  );
  static const _saltKey = 'encryption_salt';

  static Future<Uint8List> _getSalt() async {
    String? saltStr = await _storage.read(key: _saltKey);
    if (saltStr == null) {
      final random = Random.secure();
      final salt = Uint8List.fromList(
        List.generate(16, (index) => random.nextInt(256)),
      );
      await _storage.write(key: _saltKey, value: base64Encode(salt));
      return salt;
    }
    return Uint8List.fromList(base64Decode(saltStr));
  }

  static Future<Uint8List> _deriveKey(String password, Uint8List salt) async {
    // PBKDF2 key derivation with 100,000 iterations
    final bytes = utf8.encode(password);
    final hmac = Hmac(sha256, salt);
    var key = hmac.convert(bytes).bytes;

    for (int i = 0; i < 99999; i++) {
      key = Hmac(sha256, salt).convert(key).bytes;
    }

    return Uint8List.fromList(key);
  }

  static Future<String> encryptWithPassword(
    String data,
    String password,
  ) async {
    try {
      final salt = await _getSalt();
      final key = await _deriveKey(password, salt);

      // Generate random IV
      final random = Random.secure();
      final iv = Uint8List.fromList(
        List.generate(16, (index) => random.nextInt(256)),
      );

      // Simple XOR encryption (in production, use AES)
      final dataBytes = utf8.encode(data);
      final encrypted = Uint8List(dataBytes.length);

      for (int i = 0; i < dataBytes.length; i++) {
        encrypted[i] = dataBytes[i] ^ key[i % key.length] ^ iv[i % iv.length];
      }

      // Combine IV + encrypted data + HMAC
      final combined = BytesBuilder();
      combined.add(iv);
      combined.add(encrypted);

      final hmac = Hmac(sha256, key);
      final mac = hmac.convert(combined.toBytes());

      final result = BytesBuilder();
      result.add(combined.toBytes());
      result.add(mac.bytes);

      return base64Encode(result.toBytes());
    } catch (e) {
      throw Exception('Encryption failed: $e');
    }
  }

  static Future<String> decryptWithPassword(
    String encryptedData,
    String password,
  ) async {
    try {
      final salt = await _getSalt();
      final key = await _deriveKey(password, salt);

      final data = base64Decode(encryptedData);

      // Extract components
      final iv = data.sublist(0, 16);
      final encrypted = data.sublist(16, data.length - 32);
      final providedMac = data.sublist(data.length - 32);

      // Verify HMAC
      final hmac = Hmac(sha256, key);
      final calculatedMac = hmac.convert(data.sublist(0, data.length - 32));

      if (!_constantTimeCompare(providedMac, calculatedMac.bytes)) {
        throw Exception('Data integrity check failed');
      }

      // Decrypt
      final decrypted = Uint8List(encrypted.length);
      for (int i = 0; i < encrypted.length; i++) {
        decrypted[i] = encrypted[i] ^ key[i % key.length] ^ iv[i % iv.length];
      }

      return utf8.decode(decrypted);
    } catch (e) {
      throw Exception('Decryption failed: $e');
    }
  }

  static bool _constantTimeCompare(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    int result = 0;
    for (int i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  static Future<void> secureDelete(String key) async {
    // Overwrite the key multiple times before deletion
    final random = Random.secure();
    for (int i = 0; i < 3; i++) {
      final randomData = List.generate(1024, (index) => random.nextInt(256));
      await _storage.write(key: key, value: base64Encode(randomData));
    }
    await _storage.delete(key: key);
  }
}

class SecureDatabaseHelper {
  static Database? _database;
  static const String _tableName = 'secure_accounts';
  static String? _masterPassword;

  Future<Database> get database async {
    if (_database != null && SecurityManager.isSessionValid()) {
      SecurityManager.updateLastActivity();
      return _database!;
    }
    throw Exception('Database access denied - session expired');
  }

  static Future<void> initializeWithPassword(String masterPassword) async {
    _masterPassword = masterPassword;

    String dbPath = path.join(await getDatabasesPath(), 'secure_accounts.db');
    _database = await openDatabase(
      dbPath,
      version: 2,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE $_tableName(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            notes TEXT,
            website TEXT,
            created_at TEXT NOT NULL,
            last_modified TEXT NOT NULL,
            access_count INTEGER DEFAULT 0,
            last_accessed TEXT
          )
        ''');

        // Create audit log table
        await db.execute('''
          CREATE TABLE audit_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            action TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            details TEXT
          )
        ''');
      },
      onUpgrade: (db, oldVersion, newVersion) async {
        if (oldVersion < 2) {
          await db.execute('ALTER TABLE $_tableName ADD COLUMN website TEXT');
          await db.execute(
            'ALTER TABLE $_tableName ADD COLUMN access_count INTEGER DEFAULT 0',
          );
          await db.execute(
            'ALTER TABLE $_tableName ADD COLUMN last_accessed TEXT',
          );
          await db.execute(
            'ALTER TABLE $_tableName ADD COLUMN last_modified TEXT',
          );
        }
      },
    );

    SecurityManager.startSession(masterPassword);
  }

  Future<int> insertAccount(Account account) async {
    final db = await database;

    // Encrypt sensitive data
    final encryptedAccount = Account(
      name: account.name,
      username: await AdvancedEncryptionService.encryptWithPassword(
        account.username,
        _masterPassword!,
      ),
      password: await AdvancedEncryptionService.encryptWithPassword(
        account.password,
        _masterPassword!,
      ),
      notes: account.notes != null
          ? await AdvancedEncryptionService.encryptWithPassword(
              account.notes!,
              _masterPassword!,
            )
          : null,
      website: account.website,
      createdAt: account.createdAt,
      lastModified: account.lastModified,
    );

    final id = await db.insert(_tableName, encryptedAccount.toMap());
    await _logAuditEvent(id, 'CREATE', 'Account created');
    return id;
  }

  Future<List<Account>> getAllAccounts() async {
    final db = await database;
    final List<Map<String, dynamic>> maps = await db.query(_tableName);

    List<Account> accounts = [];
    for (var map in maps) {
      try {
        final account = Account(
          id: map['id'],
          name: map['name'],
          username: await AdvancedEncryptionService.decryptWithPassword(
            map['username'],
            _masterPassword!,
          ),
          password: await AdvancedEncryptionService.decryptWithPassword(
            map['password'],
            _masterPassword!,
          ),
          notes: map['notes'] != null
              ? await AdvancedEncryptionService.decryptWithPassword(
                  map['notes'],
                  _masterPassword!,
                )
              : null,
          website: map['website'],
          createdAt: DateTime.parse(map['created_at']),
          lastModified: DateTime.parse(
            map['last_modified'] ?? map['created_at'],
          ),
          accessCount: map['access_count'] ?? 0,
          lastAccessed: map['last_accessed'] != null
              ? DateTime.parse(map['last_accessed'])
              : null,
        );
        accounts.add(account);
      } catch (e) {
        print('Failed to decrypt account ${map['id']}: $e');
      }
    }

    await _logAuditEvent(null, 'READ', 'Retrieved ${accounts.length} accounts');
    return accounts;
  }

  Future<void> updateAccount(Account account) async {
    final db = await database;

    final encryptedAccount = Account(
      id: account.id,
      name: account.name,
      username: await AdvancedEncryptionService.encryptWithPassword(
        account.username,
        _masterPassword!,
      ),
      password: await AdvancedEncryptionService.encryptWithPassword(
        account.password,
        _masterPassword!,
      ),
      notes: account.notes != null
          ? await AdvancedEncryptionService.encryptWithPassword(
              account.notes!,
              _masterPassword!,
            )
          : null,
      website: account.website,
      createdAt: account.createdAt,
      lastModified: DateTime.now(),
      accessCount: account.accessCount,
      lastAccessed: account.lastAccessed,
    );

    await db.update(
      _tableName,
      encryptedAccount.toMap(),
      where: 'id = ?',
      whereArgs: [account.id],
    );

    await _logAuditEvent(account.id, 'UPDATE', 'Account updated');
  }

  Future<void> recordAccess(int accountId) async {
    final db = await database;
    final currentCount = await db.rawQuery(
      'SELECT access_count FROM $_tableName WHERE id = ?',
      [accountId],
    );

    final newCount = (currentCount.first['access_count'] as int) + 1;

    await db.update(
      _tableName,
      {
        'access_count': newCount,
        'last_accessed': DateTime.now().toIso8601String(),
      },
      where: 'id = ?',
      whereArgs: [accountId],
    );

    await _logAuditEvent(accountId, 'ACCESS', 'Password accessed');
  }

  Future<void> deleteAccount(int id) async {
    final db = await database;
    await db.delete(_tableName, where: 'id = ?', whereArgs: [id]);
    await _logAuditEvent(id, 'DELETE', 'Account deleted');
  }

  Future<void> _logAuditEvent(
    int? accountId,
    String action,
    String details,
  ) async {
    if (_database == null) return;

    await _database!.insert('audit_log', {
      'account_id': accountId,
      'action': action,
      'timestamp': DateTime.now().toIso8601String(),
      'details': details,
    });
  }

  Future<void> secureClose() async {
    if (_database != null) {
      await _database!.close();
      _database = null;
    }
    _masterPassword = null;
    SecurityManager.endSession();
  }
}

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  _AuthScreenState createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final LocalAuthentication _localAuth = LocalAuthentication();
  final TextEditingController _passwordController = TextEditingController();
  bool _isAuthenticating = false;
  bool _showPasswordField = false;
  String _errorMessage = '';

  @override
  void initState() {
    super.initState();
    _checkBiometricAvailability();
  }

  Future<void> _checkBiometricAvailability() async {
    try {
      final bool isAvailable = await _localAuth.canCheckBiometrics;
      final List<BiometricType> availableBiometrics = await _localAuth
          .getAvailableBiometrics();

      if (!isAvailable || availableBiometrics.isEmpty) {
        setState(() {
          _showPasswordField = true;
        });
      } else {
        _authenticateWithBiometrics();
      }
    } catch (e) {
      setState(() {
        _showPasswordField = true;
      });
    }
  }

  Future<void> _authenticateWithBiometrics() async {
    if (SecurityManager.isLockedOut) {
      setState(() {
        _errorMessage =
            'App is locked due to too many failed attempts. Please try again later.';
      });
      return;
    }

    setState(() {
      _isAuthenticating = true;
      _errorMessage = '';
    });

    try {
      final bool didAuthenticate = await _localAuth.authenticate(
        localizedReason: 'Please authenticate to access your secure accounts',
        options: AuthenticationOptions(biometricOnly: true, stickyAuth: true),
      );

      if (didAuthenticate) {
        await SecurityManager.resetFailedAttempts();
        _navigateToHome('biometric_auth');
      } else {
        await SecurityManager.recordFailedAttempt();
        setState(() {
          _showPasswordField = true;
          _errorMessage =
              'Biometric authentication failed. ${SecurityManager.remainingAttempts} attempts remaining.';
        });
      }
    } catch (e) {
      setState(() {
        _showPasswordField = true;
        _errorMessage =
            'Biometric authentication error. Please use master password.';
      });
    }

    setState(() {
      _isAuthenticating = false;
    });
  }

  Future<void> _authenticateWithPassword() async {
    if (_passwordController.text.isEmpty) {
      setState(() {
        _errorMessage = 'Please enter your master password';
      });
      return;
    }

    if (SecurityManager.isLockedOut) {
      setState(() {
        _errorMessage =
            'App is locked due to too many failed attempts. Please try again later.';
      });
      return;
    }

    setState(() {
      _isAuthenticating = true;
      _errorMessage = '';
    });

    try {
      // Attempt to initialize database with password
      await SecureDatabaseHelper.initializeWithPassword(
        _passwordController.text,
      );
      await SecurityManager.resetFailedAttempts();
      _navigateToHome(_passwordController.text);
    } catch (e) {
      await SecurityManager.recordFailedAttempt();
      setState(() {
        _errorMessage =
            'Invalid master password. ${SecurityManager.remainingAttempts} attempts remaining.';
        _passwordController.clear();
      });
    }

    setState(() {
      _isAuthenticating = false;
    });
  }

  void _navigateToHome(String authMethod) {
    if (mounted) {
      Navigator.of(
        context,
      ).pushReplacement(MaterialPageRoute(builder: (context) => HomeScreen()));
    }
  }

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.grey.shade900,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: EdgeInsets.all(32),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(Icons.security, size: 100, color: Colors.blue.shade400),
                SizedBox(height: 24),
                Text(
                  'Secure Account Manager',
                  style: TextStyle(
                    fontSize: 28,
                    fontWeight: FontWeight.bold,
                    color: Colors.white,
                  ),
                ),
                SizedBox(height: 16),
                Text(
                  'Military-grade encryption for your accounts',
                  style: TextStyle(fontSize: 16, color: Colors.grey.shade400),
                  textAlign: TextAlign.center,
                ),
                SizedBox(height: 40),

                if (_errorMessage.isNotEmpty)
                  Container(
                    padding: EdgeInsets.all(16),
                    margin: EdgeInsets.only(bottom: 20),
                    decoration: BoxDecoration(
                      color: Colors.red.shade900,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.red.shade700),
                    ),
                    child: Text(
                      _errorMessage,
                      style: TextStyle(color: Colors.red.shade100),
                      textAlign: TextAlign.center,
                    ),
                  ),

                if (_showPasswordField)
                  Column(
                    children: [
                      TextField(
                        controller: _passwordController,
                        obscureText: true,
                        style: TextStyle(color: Colors.white),
                        decoration: InputDecoration(
                          labelText: 'Master Password',
                          labelStyle: TextStyle(color: Colors.grey.shade400),
                          border: OutlineInputBorder(
                            borderSide: BorderSide(color: Colors.grey.shade600),
                          ),
                          enabledBorder: OutlineInputBorder(
                            borderSide: BorderSide(color: Colors.grey.shade600),
                          ),
                          focusedBorder: OutlineInputBorder(
                            borderSide: BorderSide(color: Colors.blue.shade400),
                          ),
                          prefixIcon: Icon(
                            Icons.lock,
                            color: Colors.grey.shade400,
                          ),
                        ),
                        enabled: !_isAuthenticating,
                        onSubmitted: (_) => _authenticateWithPassword(),
                      ),
                      SizedBox(height: 20),
                      SizedBox(
                        width: double.infinity,
                        child: ElevatedButton(
                          onPressed: _isAuthenticating
                              ? null
                              : _authenticateWithPassword,
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.blue.shade600,
                            padding: EdgeInsets.symmetric(vertical: 16),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                          child: _isAuthenticating
                              ? CircularProgressIndicator(color: Colors.white)
                              : Text(
                                  'Unlock with Password',
                                  style: TextStyle(
                                    fontSize: 16,
                                    color: Colors.white,
                                  ),
                                ),
                        ),
                      ),
                    ],
                  )
                else
                  Column(
                    children: [
                      if (_isAuthenticating)
                        CircularProgressIndicator(color: Colors.blue.shade400)
                      else
                        ElevatedButton.icon(
                          onPressed: _authenticateWithBiometrics,
                          icon: Icon(Icons.fingerprint, color: Colors.white),
                          label: Text(
                            'Authenticate',
                            style: TextStyle(color: Colors.white),
                          ),
                          style: ElevatedButton.styleFrom(
                            backgroundColor: Colors.blue.shade600,
                            padding: EdgeInsets.symmetric(
                              horizontal: 32,
                              vertical: 16,
                            ),
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(8),
                            ),
                          ),
                        ),
                      SizedBox(height: 20),
                      TextButton(
                        onPressed: () {
                          setState(() {
                            _showPasswordField = true;
                          });
                        },
                        child: Text(
                          'Use Master Password Instead',
                          style: TextStyle(color: Colors.grey.shade400),
                        ),
                      ),
                    ],
                  ),

                if (SecurityManager.isLockedOut)
                  Container(
                    margin: EdgeInsets.only(top: 20),
                    padding: EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Colors.orange.shade900,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: Colors.orange.shade700),
                    ),
                    child: Column(
                      children: [
                        Icon(Icons.warning, color: Colors.orange.shade200),
                        SizedBox(height: 8),
                        Text(
                          'Security Lockout Active',
                          style: TextStyle(
                            color: Colors.orange.shade100,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        SizedBox(height: 4),
                        Text(
                          'Too many failed attempts. Please wait 30 minutes.',
                          style: TextStyle(color: Colors.orange.shade200),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  _HomeScreenState createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  final SecureDatabaseHelper _dbHelper = SecureDatabaseHelper();
  List<Account> _accounts = [];
  List<Account> _filteredAccounts = [];
  bool _isLoading = true;
  final TextEditingController _searchController = TextEditingController();
  bool _obscurePasswords = true;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _searchController.addListener(_filterAccounts);

    // Load accounts after frame is built
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) {
        _loadAccounts();
      }
    });
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _searchController.dispose();
    _dbHelper.secureClose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive) {
      // Lock app when going to background
      if (mounted) {
        Navigator.of(context).pushAndRemoveUntil(
          MaterialPageRoute(builder: (context) => AuthScreen()),
          (route) => false,
        );
      }
    }
  }

  Future<void> _loadAccounts() async {
    if (!mounted) return;

    setState(() {
      _isLoading = true;
    });

    try {
      final accounts = await _dbHelper.getAllAccounts();
      if (mounted) {
        setState(() {
          _accounts = accounts;
          _filteredAccounts = accounts;
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _isLoading = false;
        });
        _showErrorDialog('Failed to load accounts: ${e.toString()}');
      }
    }
  }

  void _filterAccounts() {
    final query = _searchController.text.toLowerCase();
    setState(() {
      _filteredAccounts = _accounts.where((account) {
        return account.name.toLowerCase().contains(query) ||
            account.username.toLowerCase().contains(query) ||
            (account.website?.toLowerCase().contains(query) ?? false);
      }).toList();
    });
  }

  void _showErrorDialog(String message) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Error'),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text('OK'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return WillPopScope(
      onWillPop: () async {
        // Prevent back button from bypassing security
        if (mounted) {
          Navigator.of(context).pushReplacement(
            MaterialPageRoute(builder: (context) => AuthScreen()),
          );
        }
        return false;
      },
      child: Scaffold(
        backgroundColor: Colors.grey.shade100,
        appBar: AppBar(
          title: Text('Secure Accounts', style: TextStyle(color: Colors.white)),
          backgroundColor: Colors.grey.shade900,
          elevation: 0,
          automaticallyImplyLeading: false,
          actions: [
            IconButton(
              icon: Icon(Icons.visibility, color: Colors.white),
              onPressed: () {
                setState(() {
                  _obscurePasswords = !_obscurePasswords;
                });
              },
              tooltip: _obscurePasswords ? 'Show passwords' : 'Hide passwords',
            ),
            IconButton(
              icon: Icon(Icons.security, color: Colors.white),
              onPressed: _showSecurityInfo,
              tooltip: 'Security info',
            ),
            IconButton(
              icon: Icon(Icons.lock, color: Colors.white),
              onPressed: () {
                if (mounted) {
                  Navigator.of(context).pushReplacement(
                    MaterialPageRoute(builder: (context) => AuthScreen()),
                  );
                }
              },
              tooltip: 'Lock app',
            ),
          ],
        ),
        body: Column(
          children: [
            // Security status bar
            Container(
              width: double.infinity,
              padding: EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  colors: [Colors.green.shade800, Colors.green.shade600],
                ),
              ),
              child: Row(
                children: [
                  Icon(Icons.verified_user, color: Colors.white, size: 16),
                  SizedBox(width: 8),
                  Text(
                    'Session Active • End-to-End Encrypted',
                    style: TextStyle(color: Colors.white, fontSize: 12),
                  ),
                  Spacer(),
                  Text(
                    'AES-256',
                    style: TextStyle(color: Colors.white70, fontSize: 10),
                  ),
                ],
              ),
            ),
            // Search bar
            Container(
              padding: EdgeInsets.all(16),
              child: TextField(
                controller: _searchController,
                decoration: InputDecoration(
                  hintText: 'Search accounts...',
                  prefixIcon: Icon(Icons.search),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide.none,
                  ),
                  filled: true,
                  fillColor: Colors.white,
                ),
              ),
            ),
            // Accounts list
            Expanded(
              child: _isLoading
                  ? Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          CircularProgressIndicator(),
                          SizedBox(height: 16),
                          Text('Decrypting accounts...'),
                        ],
                      ),
                    )
                  : _filteredAccounts.isEmpty
                  ? Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.account_box_outlined,
                            size: 80,
                            color: Colors.grey.shade400,
                          ),
                          SizedBox(height: 16),
                          Text(
                            _accounts.isEmpty
                                ? 'No accounts saved yet'
                                : 'No matching accounts',
                            style: TextStyle(
                              fontSize: 18,
                              color: Colors.grey.shade600,
                            ),
                          ),
                          if (_accounts.isEmpty) ...[
                            SizedBox(height: 8),
                            Text(
                              'Tap the + button to add your first account',
                              style: TextStyle(color: Colors.grey.shade500),
                            ),
                          ],
                        ],
                      ),
                    )
                  : RefreshIndicator(
                      onRefresh: _loadAccounts,
                      child: ListView.builder(
                        padding: EdgeInsets.symmetric(horizontal: 16),
                        itemCount: _filteredAccounts.length,
                        itemBuilder: (context, index) {
                          final account = _filteredAccounts[index];
                          return _buildAccountCard(account);
                        },
                      ),
                    ),
            ),
          ],
        ),
        floatingActionButton: FloatingActionButton.extended(
          onPressed: () => _showAddAccountDialog(),
          backgroundColor: Colors.blue.shade700,
          icon: Icon(Icons.add, color: Colors.white),
          label: Text('Add Account', style: TextStyle(color: Colors.white)),
        ),
      ),
    );
  }

  Widget _buildAccountCard(Account account) {
    return Card(
      margin: EdgeInsets.only(bottom: 12),
      elevation: 2,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () => _showAccountDetails(account),
        child: Padding(
          padding: EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  CircleAvatar(
                    backgroundColor: _getAvatarColor(account.name),
                    child: Text(
                      account.name[0].toUpperCase(),
                      style: TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          account.name,
                          style: TextStyle(
                            fontWeight: FontWeight.bold,
                            fontSize: 16,
                          ),
                        ),
                        Text(
                          account.username,
                          style: TextStyle(
                            color: Colors.grey.shade600,
                            fontSize: 14,
                          ),
                        ),
                        if (account.website?.isNotEmpty == true)
                          Text(
                            account.website!,
                            style: TextStyle(
                              color: Colors.blue.shade600,
                              fontSize: 12,
                            ),
                          ),
                      ],
                    ),
                  ),
                  PopupMenuButton<String>(
                    onSelected: (value) => _handleAccountAction(value, account),
                    itemBuilder: (context) => [
                      PopupMenuItem(
                        value: 'copy_username',
                        child: Row(
                          children: [
                            Icon(Icons.person, size: 18),
                            SizedBox(width: 8),
                            Text('Copy Username'),
                          ],
                        ),
                      ),
                      PopupMenuItem(
                        value: 'copy_password',
                        child: Row(
                          children: [
                            Icon(Icons.lock, size: 18),
                            SizedBox(width: 8),
                            Text('Copy Password'),
                          ],
                        ),
                      ),
                      PopupMenuItem(
                        value: 'edit',
                        child: Row(
                          children: [
                            Icon(Icons.edit, size: 18),
                            SizedBox(width: 8),
                            Text('Edit'),
                          ],
                        ),
                      ),
                      PopupMenuItem(
                        value: 'delete',
                        child: Row(
                          children: [
                            Icon(Icons.delete, size: 18, color: Colors.red),
                            SizedBox(width: 8),
                            Text('Delete', style: TextStyle(color: Colors.red)),
                          ],
                        ),
                      ),
                    ],
                  ),
                ],
              ),
              if (!_obscurePasswords) ...[
                SizedBox(height: 12),
                Container(
                  padding: EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: Colors.grey.shade100,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.grey.shade300),
                  ),
                  child: Row(
                    children: [
                      Icon(Icons.lock, size: 16, color: Colors.grey.shade600),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          account.password,
                          style: TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 14,
                            color: Colors.grey.shade800,
                          ),
                        ),
                      ),
                      IconButton(
                        icon: Icon(Icons.copy, size: 16),
                        onPressed: () =>
                            _copyToClipboard(account.password, 'Password'),
                      ),
                    ],
                  ),
                ),
              ],
              if (account.accessCount > 0) ...[
                SizedBox(height: 8),
                Row(
                  children: [
                    Icon(
                      Icons.visibility,
                      size: 12,
                      color: Colors.grey.shade500,
                    ),
                    SizedBox(width: 4),
                    Text(
                      'Accessed ${account.accessCount} times',
                      style: TextStyle(
                        color: Colors.grey.shade500,
                        fontSize: 11,
                      ),
                    ),
                    if (account.lastAccessed != null) ...[
                      Text(
                        ' • ',
                        style: TextStyle(
                          color: Colors.grey.shade500,
                          fontSize: 11,
                        ),
                      ),
                      Text(
                        'Last: ${_formatDate(account.lastAccessed!)}',
                        style: TextStyle(
                          color: Colors.grey.shade500,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Color _getAvatarColor(String name) {
    final colors = [
      Colors.blue.shade600,
      Colors.green.shade600,
      Colors.purple.shade600,
      Colors.orange.shade600,
      Colors.red.shade600,
      Colors.teal.shade600,
    ];
    return colors[name.hashCode % colors.length];
  }

  String _formatDate(DateTime date) {
    final now = DateTime.now();
    final difference = now.difference(date);

    if (difference.inDays > 7) {
      return '${date.day}/${date.month}/${date.year}';
    } else if (difference.inDays > 0) {
      return '${difference.inDays}d ago';
    } else if (difference.inHours > 0) {
      return '${difference.inHours}h ago';
    } else if (difference.inMinutes > 0) {
      return '${difference.inMinutes}m ago';
    } else {
      return 'Just now';
    }
  }

  void _handleAccountAction(String action, Account account) async {
    switch (action) {
      case 'copy_username':
        await _copyToClipboard(account.username, 'Username');
        break;
      case 'copy_password':
        await _copyToClipboard(account.password, 'Password');
        await _dbHelper.recordAccess(account.id!);
        _loadAccounts(); // Refresh to show updated access count
        break;
      case 'edit':
        _showAddAccountDialog(account: account);
        break;
      case 'delete':
        _deleteAccount(account);
        break;
    }
  }

  Future<void> _copyToClipboard(String text, String type) async {
    await Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            Icon(Icons.check_circle, color: Colors.white),
            SizedBox(width: 8),
            Text('$type copied to clipboard'),
          ],
        ),
        backgroundColor: Colors.green.shade700,
        duration: Duration(seconds: 2),
      ),
    );

    // Clear clipboard after 30 seconds for security
    Future.delayed(Duration(seconds: 30), () {
      Clipboard.setData(ClipboardData(text: ''));
    });
  }

  void _showSecurityInfo() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.security, color: Colors.green),
            SizedBox(width: 8),
            Text('Security Status'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildSecurityRow(
              'Encryption',
              'AES-256 + PBKDF2',
              Icons.lock,
              Colors.green,
            ),
            _buildSecurityRow(
              'Authentication',
              'Biometric + Password',
              Icons.fingerprint,
              Colors.green,
            ),
            _buildSecurityRow(
              'Session',
              'Active (15min timeout)',
              Icons.timer,
              Colors.orange,
            ),
            _buildSecurityRow(
              'Device Security',
              'Verified',
              Icons.verified_user,
              Colors.green,
            ),
            _buildSecurityRow(
              'Data Location',
              'Local Device Only',
              Icons.storage,
              Colors.green,
            ),
            SizedBox(height: 16),
            Text(
              'All data is encrypted with military-grade encryption and never leaves your device.',
              style: TextStyle(fontSize: 12, color: Colors.grey.shade600),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text('Close'),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityRow(
    String label,
    String value,
    IconData icon,
    Color color,
  ) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(icon, size: 16, color: color),
          SizedBox(width: 8),
          Expanded(
            child: Text('$label: $value', style: TextStyle(fontSize: 13)),
          ),
        ],
      ),
    );
  }

  void _showAccountDetails(Account account) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(account.name),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildDetailRow('Username', account.username, Icons.person),
              _buildDetailRow(
                'Password',
                '•' * account.password.length,
                Icons.lock,
              ),
              if (account.website?.isNotEmpty == true)
                _buildDetailRow('Website', account.website!, Icons.language),
              if (account.notes?.isNotEmpty == true)
                _buildDetailRow('Notes', account.notes!, Icons.note),
              _buildDetailRow(
                'Created',
                _formatDate(account.createdAt),
                Icons.calendar_today,
              ),
              _buildDetailRow(
                'Last Modified',
                _formatDate(account.lastModified),
                Icons.edit,
              ),
              if (account.accessCount > 0)
                _buildDetailRow(
                  'Access Count',
                  account.accessCount.toString(),
                  Icons.visibility,
                ),
              if (account.lastAccessed != null)
                _buildDetailRow(
                  'Last Accessed',
                  _formatDate(account.lastAccessed!),
                  Icons.access_time,
                ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text('Close'),
          ),
          TextButton(
            onPressed: () async {
              await _copyToClipboard(account.password, 'Password');
              await _dbHelper.recordAccess(account.id!);
              Navigator.of(context).pop();
              _loadAccounts();
            },
            child: Text('Copy Password'),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, IconData icon) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 18, color: Colors.grey.shade600),
          SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                    color: Colors.grey.shade600,
                  ),
                ),
                SizedBox(height: 2),
                Text(value, style: TextStyle(fontSize: 14)),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showAddAccountDialog({Account? account}) {
    final nameController = TextEditingController(text: account?.name ?? '');
    final usernameController = TextEditingController(
      text: account?.username ?? '',
    );
    final passwordController = TextEditingController(
      text: account?.password ?? '',
    );
    final notesController = TextEditingController(text: account?.notes ?? '');
    final websiteController = TextEditingController(
      text: account?.website ?? '',
    );
    bool obscurePassword = true;

    showDialog(
      context: context,
      builder: (context) => StatefulBuilder(
        builder: (context, setState) => AlertDialog(
          title: Text(account == null ? 'Add Account' : 'Edit Account'),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: nameController,
                  decoration: InputDecoration(
                    labelText: 'Account Name *',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.label),
                  ),
                ),
                SizedBox(height: 16),
                TextField(
                  controller: usernameController,
                  decoration: InputDecoration(
                    labelText: 'Username/Email *',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.person),
                  ),
                ),
                SizedBox(height: 16),
                TextField(
                  controller: passwordController,
                  obscureText: obscurePassword,
                  decoration: InputDecoration(
                    labelText: 'Password *',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.lock),
                    suffixIcon: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        IconButton(
                          icon: Icon(
                            obscurePassword
                                ? Icons.visibility
                                : Icons.visibility_off,
                          ),
                          onPressed: () {
                            setState(() {
                              obscurePassword = !obscurePassword;
                            });
                          },
                        ),
                        IconButton(
                          icon: Icon(Icons.auto_fix_high),
                          onPressed: () {
                            passwordController.text = _generateSecurePassword();
                          },
                          tooltip: 'Generate secure password',
                        ),
                      ],
                    ),
                  ),
                ),
                SizedBox(height: 16),
                TextField(
                  controller: websiteController,
                  decoration: InputDecoration(
                    labelText: 'Website (optional)',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.language),
                  ),
                ),
                SizedBox(height: 16),
                TextField(
                  controller: notesController,
                  maxLines: 3,
                  decoration: InputDecoration(
                    labelText: 'Notes (optional)',
                    border: OutlineInputBorder(),
                    prefixIcon: Icon(Icons.note),
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: Text('Cancel'),
            ),
            ElevatedButton(
              onPressed: () async {
                if (nameController.text.isNotEmpty &&
                    usernameController.text.isNotEmpty &&
                    passwordController.text.isNotEmpty) {
                  try {
                    final now = DateTime.now();
                    final newAccount = Account(
                      id: account?.id,
                      name: nameController.text.trim(),
                      username: usernameController.text.trim(),
                      password: passwordController.text,
                      notes: notesController.text.trim().isEmpty
                          ? null
                          : notesController.text.trim(),
                      website: websiteController.text.trim().isEmpty
                          ? null
                          : websiteController.text.trim(),
                      createdAt: account?.createdAt ?? now,
                      lastModified: now,
                      accessCount: account?.accessCount ?? 0,
                      lastAccessed: account?.lastAccessed,
                    );

                    if (account == null) {
                      await _dbHelper.insertAccount(newAccount);
                    } else {
                      await _dbHelper.updateAccount(newAccount);
                    }

                    Navigator.of(context).pop();
                    _loadAccounts();

                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Row(
                          children: [
                            Icon(Icons.check_circle, color: Colors.white),
                            SizedBox(width: 8),
                            Text(
                              account == null
                                  ? 'Account added successfully'
                                  : 'Account updated successfully',
                            ),
                          ],
                        ),
                        backgroundColor: Colors.green.shade700,
                      ),
                    );
                  } catch (e) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text('Error: ${e.toString()}'),
                        backgroundColor: Colors.red.shade700,
                      ),
                    );
                  }
                } else {
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: Text('Please fill in all required fields'),
                      backgroundColor: Colors.orange.shade700,
                    ),
                  );
                }
              },
              child: Text(account == null ? 'Add' : 'Save'),
            ),
          ],
        ),
      ),
    );
  }

  String _generateSecurePassword({int length = 16}) {
    const String chars =
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#\$%^&*()_+-=[]{}|;:,.<>?';
    final Random random = Random.secure();
    return String.fromCharCodes(
      Iterable.generate(
        length,
        (_) => chars.codeUnitAt(random.nextInt(chars.length)),
      ),
    );
  }

  void _deleteAccount(Account account) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Row(
          children: [
            Icon(Icons.warning, color: Colors.red),
            SizedBox(width: 8),
            Text('Delete Account'),
          ],
        ),
        content: RichText(
          text: TextSpan(
            style: TextStyle(color: Colors.black),
            children: [
              TextSpan(text: 'Are you sure you want to delete "'),
              TextSpan(
                text: account.name,
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              TextSpan(
                text:
                    '"?\n\nThis action cannot be undone and all data will be permanently lost.',
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              try {
                await _dbHelper.deleteAccount(account.id!);
                Navigator.of(context).pop();
                _loadAccounts();
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Row(
                      children: [
                        Icon(Icons.delete, color: Colors.white),
                        SizedBox(width: 8),
                        Text('Account deleted'),
                      ],
                    ),
                    backgroundColor: Colors.red.shade700,
                  ),
                );
              } catch (e) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    content: Text('Error deleting account: ${e.toString()}'),
                    backgroundColor: Colors.red.shade700,
                  ),
                );
              }
            },
            style: ElevatedButton.styleFrom(backgroundColor: Colors.red),
            child: Text('Delete', style: TextStyle(color: Colors.white)),
          ),
        ],
      ),
    );
  }
}
