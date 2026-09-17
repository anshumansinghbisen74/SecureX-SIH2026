import 'package:flutter_test/flutter_test.dart';
import 'package:securex_frontend/main.dart';

void main() {
  testWidgets('SecureX login screen renders', (tester) async {
    await tester.pumpWidget(const SecureXApp());
    expect(find.text("Secure'X"), findsOneWidget);
    expect(find.text('SIGN IN'), findsOneWidget);
    expect(find.text('Protected evidence. Verifiable trust.'), findsOneWidget);
  });
}
