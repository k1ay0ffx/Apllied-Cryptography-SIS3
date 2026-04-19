/**
 * Main — точка входа RSA приложения.
 *
 * ╔══════════════════════════════════════════════════════════╗
 * ║  Чтобы подключить реализацию другого разработчика:       ║
 * ║                                                          ║
 * ║  1. Убедись что класс RSAEngine implements IRSAEngine    ║
 * ║  2. Замени:  new RSAEngineStub()                         ║
 * ║     На:      new RSAEngine()                             ║
 * ║  3. Добавь import если нужно                             ║
 * ╚══════════════════════════════════════════════════════════╝
 */
public class Main {
    public static void main(String[] args) {

        // ── ЗДЕСЬ МЕНЯЕТСЯ ДВИЖОК ──────────────────────────────────────────
        // Стаб (заглушка) — работает, использует BigInteger.probablePrime()
        IRSAEngine engine = new RSAEngine();

        // После пуша другого разработчика → замени на:
        // IRSAEngine engine = new RSAEngine();
        // ──────────────────────────────────────────────────────────────────

        RSAConsole console = new RSAConsole(engine);
        console.run();
    }
}