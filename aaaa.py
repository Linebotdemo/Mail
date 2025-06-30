import sqlite3
import json

DB_PATH = 'database.db'  # 必要に応じてパスを調整してください

def check_campaigns():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT * FROM campaigns')
        rows = cursor.fetchall()

        for row in rows:
            print("📝 キャンペーンID:", row["id"])
            print("   部署:", row["department"])
            print("   開始日:", row["start_date"])
            print("   終了日:", row["end_date"])
            print("   テンプレートIDリスト:", row["template_ids"])
            # テンプレートIDリストをデコードして表示
            try:
                template_ids = json.loads(row["template_ids"] or '[]')
                print("   デコード結果（リスト）:", template_ids)
            except Exception as e:
                print("   ⚠ テンプレートIDのデコード失敗:", e)

            print("-" * 40)

    except Exception as e:
        print("❌ データ取得エラー:", e)
    finally:
        conn.close()

if __name__ == '__main__':
    check_campaigns()
