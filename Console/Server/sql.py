import sqlite3

conn = sqlite3.connect('data.db')
c = conn.cursor()

c.execute(
    """
    select * from user

    """
)
data = c.fetchall()
print(data[0][1])
conn.commit()
conn.close()