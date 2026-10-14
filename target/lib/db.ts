import Database from "better-sqlite3";

// やられ役ECサイト（猫ショップ「NEKO MART」）の疑似データベース。
// SQLインジェクションを“本物”として再現するため、実際の SQLite を使う。
// 格納するのはすべてダミーの架空データ（実在の個人情報は一切含まない）。

declare global {
  // eslint-disable-next-line no-var
  var __antibodyDb: Database.Database | undefined;
}

function seed(db: Database.Database) {
  db.exec(`
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS products;
    DROP TABLE IF EXISTS orders;
    DROP TABLE IF EXISTS reviews;

    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      role TEXT,
      email TEXT,
      credit_card TEXT
    );
    CREATE TABLE products (
      id INTEGER PRIMARY KEY,
      name TEXT,
      price INTEGER,
      description TEXT,
      emoji TEXT
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY,
      user_id INTEGER,
      total INTEGER,
      items TEXT,
      address TEXT
    );
    CREATE TABLE reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER,
      author TEXT,
      body TEXT,
      created_at TEXT
    );
  `);

  // すべて架空のダミーデータ。credit_card はテスト用の無効番号。
  const users: [number, string, string, string, string, string][] = [
    [1, "admin", "S3cr3t!admin", "admin", "admin@neko.example", "4111-1111-1111-1111"],
    [2, "tanaka", "tanaka123", "user", "tanaka@neko.example", "4222-2222-2222-2222"],
    [3, "suzuki", "suzuki123", "user", "suzuki@neko.example", "4333-3333-3333-3333"],
  ];
  const insUser = db.prepare(
    "INSERT INTO users (id, username, password, role, email, credit_card) VALUES (?,?,?,?,?,?)"
  );
  for (const u of users) insUser.run(...u);

  const products: [number, string, number, string, string][] = [
    [1, "またたびキャットタワー", 12800, "三毛猫も満足の大型タワー", "🐱"],
    [2, "ふわふわ爪とぎソファ", 4800, "ガリガリ最高の肌触り", "🛋️"],
    [3, "自動給餌器 みけ3000", 9800, "留守番も安心の自動給餌", "🍚"],
    [4, "またたびボール 5個組", 980, "猫が夢中になるおもちゃ", "⚽"],
    [5, "もふもふ毛布 こたつ猫", 3200, "冬の必需品あったか毛布", "🧶"],
  ];
  const insProd = db.prepare(
    "INSERT INTO products (id, name, price, description, emoji) VALUES (?,?,?,?,?)"
  );
  for (const p of products) insProd.run(...p);

  const orders: [number, number, number, string, string][] = [
    [1001, 2, 17600, JSON.stringify([{ id: 1, qty: 1 }, { id: 2, qty: 1 }]), "東京都渋谷区1-2-3"],
    [1002, 3, 9800, JSON.stringify([{ id: 3, qty: 1 }]), "大阪府大阪市4-5-6"],
    [1003, 2, 980, JSON.stringify([{ id: 4, qty: 1 }]), "東京都渋谷区1-2-3"],
  ];
  const insOrder = db.prepare(
    "INSERT INTO orders (id, user_id, total, items, address) VALUES (?,?,?,?,?)"
  );
  for (const o of orders) insOrder.run(...o);

  const insReview = db.prepare(
    "INSERT INTO reviews (product_id, author, body, created_at) VALUES (?,?,?,?)"
  );
  insReview.run(1, "ねこ好き太郎", "うちの猫が大喜びでした！", new Date().toISOString());
  insReview.run(1, "みけママ", "安定感があって安心です", new Date().toISOString());
}

export function getDb(): Database.Database {
  if (!globalThis.__antibodyDb) {
    const db = new Database(":memory:");
    db.pragma("journal_mode = WAL");
    seed(db);
    globalThis.__antibodyDb = db;
  }
  return globalThis.__antibodyDb;
}

/** DB を初期状態に戻す（デモのやり直し／reset 用）。 */
export function reseedDb(): void {
  const db = getDb();
  seed(db);
}
