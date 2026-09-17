import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

const apiBase = String.fromEnvironment('SECUREX_API', defaultValue: 'http://127.0.0.1:8000');

void main() => runApp(const SecureXApp());

class SecureXApp extends StatelessWidget {
  const SecureXApp({super.key});

  @override
  Widget build(BuildContext context) => MaterialApp(
        debugShowCheckedModeBanner: false,
        title: "Secure'X",
        theme: ThemeData(
          brightness: Brightness.dark,
          colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff23d6b5), brightness: Brightness.dark),
          scaffoldBackgroundColor: const Color(0xff081116),
          cardTheme: const CardThemeData(color: Color(0xff101e25), margin: EdgeInsets.zero),
          useMaterial3: true,
        ),
        home: const LoginPage(),
      );
}

class Api {
  static String? token;
  static String? refreshToken;

  static Map<String, String> headers({bool json = true}) => {
        if (json) 'Content-Type': 'application/json',
        if (token != null) 'Authorization': 'Bearer $token',
      };

  static Future<http.Response> get(String path) => http.get(Uri.parse('$apiBase$path'), headers: headers());

  static Future<http.Response> post(String path, Object body) => http.post(Uri.parse('$apiBase$path'), headers: headers(), body: jsonEncode(body));

  static Future<void> rotateRefreshToken() async {
    if (refreshToken == null) throw Exception('Session expired');
    final response = await http.post(Uri.parse('$apiBase/auth/refresh'), headers: {'Content-Type': 'application/json'}, body: jsonEncode({'refresh_token': refreshToken}));
    if (response.statusCode != 200) throw Exception('Session expired');
    final data = jsonDecode(response.body);
    token = data['access_token'];
    refreshToken = data['refresh_token'];
  }

  static Future<http.Response> download(String path, {Map<String, String>? extraHeaders}) async {
    var requestHeaders = headers(json: false);
    if (extraHeaders != null) requestHeaders.addAll(extraHeaders);
    var response = await http.get(Uri.parse('$apiBase$path'), headers: requestHeaders);
    if (response.statusCode == 401 && refreshToken != null) {
      await rotateRefreshToken();
      requestHeaders = headers(json: false);
      if (extraHeaders != null) requestHeaders.addAll(extraHeaders);
      response = await http.get(Uri.parse('$apiBase$path'), headers: requestHeaders);
    }
    return response;
  }

  static Future<http.Response> releaseKey(String path, Map<String, dynamic> body) async {
    var response = await http.post(Uri.parse('$apiBase$path'), headers: headers(), body: jsonEncode(body));
    if (response.statusCode == 401 && refreshToken != null) {
      await rotateRefreshToken();
      response = await http.post(Uri.parse('$apiBase$path'), headers: headers(), body: jsonEncode(body));
    }
    return response;
  }
}

class LoginPage extends StatefulWidget {
  const LoginPage({super.key});
  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final email = TextEditingController();
  final password = TextEditingController();
  bool busy = false;
  String? error;

  Future<void> login() async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      final response = await http.post(Uri.parse('$apiBase/auth/login'), headers: {'Content-Type': 'application/json'}, body: jsonEncode({'email': email.text, 'password': password.text}));
      if (response.statusCode != 200) throw Exception(jsonDecode(response.body)['detail'] ?? 'Login failed');
      final data = jsonDecode(response.body);
      Api.token = data['access_token'];
      Api.refreshToken = data['refresh_token'];
      if (mounted) Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => const DashboardPage()));
    } catch (e) {
      if (mounted) setState(() => error = e.toString());
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 440),
            child: Card(
              child: Padding(
                padding: const EdgeInsets.all(28),
                child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
                  const Icon(Icons.shield_outlined, size: 48, color: Color(0xff23d6b5)),
                  const SizedBox(height: 16),
                  Text("Secure'X", style: Theme.of(context).textTheme.headlineMedium?.copyWith(fontWeight: FontWeight.bold)),
                  const Text('Protected evidence. Verifiable trust.', style: TextStyle(color: Colors.white60)),
                  const SizedBox(height: 28),
                  TextField(controller: email, decoration: const InputDecoration(labelText: 'Email', prefixIcon: Icon(Icons.alternate_email))),
                  const SizedBox(height: 12),
                  TextField(controller: password, obscureText: true, decoration: const InputDecoration(labelText: 'Password', prefixIcon: Icon(Icons.key))),
                  if (error != null) Padding(padding: const EdgeInsets.only(top: 12), child: Text(error!, style: const TextStyle(color: Colors.redAccent))),
                  const SizedBox(height: 22),
                  SizedBox(width: double.infinity, child: FilledButton.icon(onPressed: busy ? null : login, icon: const Icon(Icons.login), label: Text(busy ? 'AUTHENTICATING...' : 'SIGN IN'))),
                  const SizedBox(height: 18),
                  const Text('Use credentials provisioned by your local administrator.', style: TextStyle(color: Colors.white54, fontSize: 12)),
                ]),
              ),
            ),
          ),
        ),
      );
}

class DashboardPage extends StatefulWidget {
  const DashboardPage({super.key});
  @override
  State<DashboardPage> createState() => _DashboardPageState();
}

class _DashboardPageState extends State<DashboardPage> {
  int tab = 0;
  List<dynamic> cases = [], documents = [], audit = [];
  bool loading = true;

  @override
  void initState() {
    super.initState();
    refresh();
  }

  Future<void> refresh() async {
    setState(() => loading = true);
    final responses = await Future.wait([Api.get('/cases'), Api.get('/documents'), Api.get('/audit')]);
    if (!mounted) return;
    setState(() {
      cases = responses[0].statusCode == 200 ? jsonDecode(responses[0].body) : [];
      documents = responses[1].statusCode == 200 ? jsonDecode(responses[1].body) : [];
      audit = responses[2].statusCode == 200 ? jsonDecode(responses[2].body) : [];
      loading = false;
    });
  }

  Future<void> logout() async {
    final current = Api.refreshToken;
    if (current != null) {
      await http.post(Uri.parse('$apiBase/auth/logout'), headers: {'Content-Type': 'application/json'}, body: jsonEncode({'refresh_token': current}));
    }
    Api.token = null;
    Api.refreshToken = null;
    if (mounted) Navigator.of(context).pushReplacement(MaterialPageRoute(builder: (_) => const LoginPage()));
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text("SECURE'X"), actions: [IconButton(onPressed: refresh, icon: const Icon(Icons.refresh)), IconButton(onPressed: logout, icon: const Icon(Icons.logout))]),
        body: loading ? const Center(child: CircularProgressIndicator()) : IndexedStack(index: tab, children: [_overview(), _cases(), _documents(), _audit()]),
        bottomNavigationBar: NavigationBar(selectedIndex: tab, onDestinationSelected: (i) => setState(() => tab = i), destinations: const [
          NavigationDestination(icon: Icon(Icons.dashboard_outlined), label: 'Dashboard'),
          NavigationDestination(icon: Icon(Icons.folder_outlined), label: 'Cases'),
          NavigationDestination(icon: Icon(Icons.lock_outline), label: 'Documents'),
          NavigationDestination(icon: Icon(Icons.timeline), label: 'Audit'),
        ]),
        floatingActionButton: tab == 1 ? FloatingActionButton.extended(onPressed: createCase, icon: const Icon(Icons.add), label: const Text('NEW CASE')) : tab == 2 ? FloatingActionButton.extended(onPressed: upload, icon: const Icon(Icons.upload_file), label: const Text('PROTECT')) : null,
      );

  Widget _overview() => RefreshIndicator(
        onRefresh: refresh,
        child: ListView(padding: const EdgeInsets.all(20), children: [
          Text('Security overview', style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 8),
          const Text('Real-time posture from the protected backend.', style: TextStyle(color: Colors.white60)),
          const SizedBox(height: 20),
          Wrap(spacing: 12, runSpacing: 12, children: [
            _metric('PROTECTED DOCUMENTS', documents.length.toString(), Icons.description_outlined, Colors.cyan),
            _metric('ACTIVE CASES', cases.length.toString(), Icons.folder_shared_outlined, Colors.amber),
            _metric('AUDIT EVENTS', audit.length.toString(), Icons.verified_user_outlined, Colors.green),
            _metric('ENCRYPTION', 'AES-256-GCM', Icons.lock_outline, Colors.purple),
          ]),
          const SizedBox(height: 28),
          Text('Recent activity', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 10),
          ...audit.take(8).map((e) => ListTile(leading: const Icon(Icons.shield, color: Colors.teal), title: Text(e['event_type']), subtitle: Text(e['document_id'] ?? 'System event'))),
        ]),
      );

  Widget _metric(String title, String value, IconData icon, Color color) => SizedBox(width: 230, child: Card(child: Padding(padding: const EdgeInsets.all(18), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Icon(icon, color: color), const SizedBox(height: 16), Text(value, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)), Text(title, style: const TextStyle(color: Colors.white60, fontSize: 11))]))));

  Widget _cases() => ListView(padding: const EdgeInsets.all(20), children: [
        Text('Authorized cases', style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 16),
        ...cases.map((c) => Card(child: ListTile(leading: const Icon(Icons.folder_special, color: Colors.amber), title: Text(c['case_number']), subtitle: Text('${c['title']}\n${c['case_type']} · ${c['status']}'), isThreeLine: true))),
      ]);

  Widget _documents() => ListView(padding: const EdgeInsets.all(20), children: [
        Text('Protected documents', style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 16),
        ...documents.map((d) => Card(child: ListTile(onTap: () => openDocument(d), leading: const Icon(Icons.lock, color: Colors.teal), title: Text(d['name']), subtitle: Text('${d['classification']} · v${d['latest_version']}'), trailing: IconButton(icon: const Icon(Icons.verified_outlined), onPressed: () => verify(d['id']))))),
      ]);

  Widget _audit() => ListView(padding: const EdgeInsets.all(20), children: [
        Text('Tamper-evident audit trail', style: Theme.of(context).textTheme.headlineSmall),
        const SizedBox(height: 16),
        ...audit.map((e) => Card(child: ListTile(leading: const Icon(Icons.link, color: Colors.teal), title: Text(e['event_type']), subtitle: Text('${e['timestamp']}\n${e['event_hash']}'), isThreeLine: true))),
      ]);

  Future<void> createCase() async {
    final number = TextEditingController(), title = TextEditingController();
    await showDialog(context: context, builder: (_) => AlertDialog(title: const Text('Create case'), content: Column(mainAxisSize: MainAxisSize.min, children: [TextField(controller: number, decoration: const InputDecoration(labelText: 'Case number')), TextField(controller: title, decoration: const InputDecoration(labelText: 'Title'))]), actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')), FilledButton(onPressed: () async { final r = await Api.post('/cases', {'case_number': number.text, 'title': title.text}); if (r.statusCode == 201 && mounted) { Navigator.pop(context); refresh(); } }, child: const Text('Create'))]));
  }

  Future<void> upload() async {
    if (cases.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Create or assign a case first.')));
      return;
    }
    final result = await FilePicker.platform.pickFiles(withData: false);
    if (result == null || result.files.single.path == null || !mounted) return;
    final request = http.MultipartRequest('POST', Uri.parse('$apiBase/documents/upload'))
      ..headers['Authorization'] = 'Bearer ${Api.token}'
      ..fields['case_id'] = cases.first['id']
      ..files.add(await http.MultipartFile.fromPath('file', result.files.single.path!));
    final response = await request.send();
    final body = await response.stream.bytesToString();
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(response.statusCode == 201 ? 'Encrypted and stored: ${jsonDecode(body)['name']}' : 'Upload failed: $body')));
    if (response.statusCode == 201) refresh();
  }

  Future<void> verify(String id) async {
    final r = await Api.get('/documents/$id/verify');
    if (!mounted) return;
    final data = jsonDecode(r.body);
    showDialog(context: context, builder: (_) => AlertDialog(title: Text(data['status']), content: SelectableText('Expected: ${data['expected_hash']}\nActual: ${data['actual_hash']}'), actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close'))]));
    refresh();
  }

  void openDocument(dynamic document) {
    Navigator.of(context).push(MaterialPageRoute(builder: (_) => SecureDocumentPage(document: document)));
  }
}

class SecureDocumentPage extends StatefulWidget {
  final dynamic document;
  const SecureDocumentPage({super.key, required this.document});
  @override
  State<SecureDocumentPage> createState() => _SecureDocumentPageState();
}

class _SecureDocumentPageState extends State<SecureDocumentPage> {
  bool loading = true;
  String? error;
  Uint8List? plaintext;
  String? contentType;
  Map<String, dynamic>? verification;
  Map<String, dynamic>? blockchain;

  @override
  void initState() {
    super.initState();
    load();
  }

  Future<void> load() async {
    try {
      final detailResponse = await Api.get('/documents/${widget.document['id']}');
      final detail = detailResponse.statusCode == 200 ? jsonDecode(detailResponse.body) : <String, dynamic>{};
      final keyPair = await X25519().newKeyPair();
      final clientPublic = await keyPair.extractPublicKey();
      final releaseResponse = await Api.releaseKey(
        '/documents/${widget.document['id']}/key-release',
        {'client_public_key': base64Encode(clientPublic.bytes)},
      );
      if (releaseResponse.statusCode != 200) {
        throw Exception(jsonDecode(releaseResponse.body)['detail'] ?? 'Key release denied');
      }
      final release = jsonDecode(releaseResponse.body) as Map<String, dynamic>;
      final serverPublic = SimplePublicKey(
        base64Decode(release['server_public_key']),
        type: KeyPairType.x25519,
      );
      final shared = await X25519().sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: serverPublic,
      );
      final envelopeKey = await Hkdf(
        hmac: Hmac.sha256(),
        outputLength: 32,
      ).deriveKey(
        secretKey: shared,
        nonce: base64Decode(release['salt']),
        info: utf8.encode('securex-key-release:${widget.document['id']}'),
      );
      final wrappedDek = base64Decode(release['ciphertext']);
      if (wrappedDek.length < 16) throw Exception('Invalid key envelope');
      final dek = await AesGcm.with256bits().decrypt(
        SecretBox(
          wrappedDek.sublist(0, wrappedDek.length - 16),
          nonce: base64Decode(release['nonce']),
          mac: Mac(wrappedDek.sublist(wrappedDek.length - 16)),
        ),
        secretKey: envelopeKey,
        aad: utf8.encode(widget.document['id']),
      );
      final encrypted = await Api.download(
        '/documents/${widget.document['id']}/download',
        extraHeaders: {'X-SecureX-Release-Token': release['release_token']},
      );
      if (encrypted.statusCode != 200) throw Exception(jsonDecode(encrypted.body)['detail'] ?? 'Access denied');
      final nonce = base64Decode(encrypted.headers['x-securex-nonce']!);
      final bytes = encrypted.bodyBytes;
      if (bytes.length < 16) throw Exception('Invalid encrypted payload');
      final secretBox = SecretBox(bytes.sublist(0, bytes.length - 16), nonce: nonce, mac: Mac(bytes.sublist(bytes.length - 16)));
      final clear = await AesGcm.with256bits().decrypt(secretBox, secretKey: SecretKey(dek));
      final verifyResponse = await Api.get('/documents/${widget.document['id']}/verify');
      final chainResponse = await Api.get('/documents/${widget.document['id']}/blockchain/verify');
      if (!mounted) return;
      setState(() {
        plaintext = Uint8List.fromList(clear);
        contentType = detail['content_type'];
        verification = verifyResponse.statusCode == 200 ? jsonDecode(verifyResponse.body) : null;
        blockchain = chainResponse.statusCode == 200 ? jsonDecode(chainResponse.body) : null;
        loading = false;
      });
    } catch (e) {
      if (mounted) setState(() { error = e.toString(); loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Secure document')),
        body: loading
            ? const Center(child: CircularProgressIndicator())
            : error != null
                ? Center(child: Padding(padding: const EdgeInsets.all(24), child: Text(error!, textAlign: TextAlign.center)))
                : ListView(padding: const EdgeInsets.all(20), children: [
                    Text(widget.document['name'], style: Theme.of(context).textTheme.headlineSmall),
                    const SizedBox(height: 8),
                    const Text('Temporary in-memory rendering only', style: TextStyle(color: Colors.teal)),
                    const SizedBox(height: 16),
                    Card(child: Padding(padding: const EdgeInsets.all(16), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text('Integrity: ${verification?['status'] ?? 'UNAVAILABLE'}'),
                      Text('Blockchain: ${blockchain?['status'] ?? 'UNAVAILABLE'}'),
                      const Text('Authorization: ACTIVE'),
                    ]))),
                    const SizedBox(height: 16),
                    _renderContent(),
                  ]),
      );

  Widget _renderContent() {
    final bytes = plaintext!;
    if ((contentType ?? '').startsWith('image/')) return Image.memory(bytes, fit: BoxFit.contain);
    return Card(child: Padding(padding: const EdgeInsets.all(16), child: SelectableText(utf8.decode(bytes, allowMalformed: true))));
  }
}
