import sqlite3

conn = sqlite3.connect('products.db')

# Add a nonnegative stock constraint (if not already present)
try:
    conn.execute("ALTER TABLE products ADD CONSTRAINT stock_nonnegative CHECK (stock >= 0);")
    print("Constraint added.")
except sqlite3.OperationalError as e:
    print("Skipping constraint (it may already exist):", e)

# Try to update stock
try:
    conn.execute("UPDATE products SET stock = stock - 1 WHERE product_id = 'top1_women'")
    conn.commit()
    row = conn.execute("SELECT product_id, stock FROM products WHERE product_id = 'top1_women'").fetchone()
    print(row)
except sqlite3.IntegrityError as e:
    print("Update failed due to stock constraint:", e)

conn.close()