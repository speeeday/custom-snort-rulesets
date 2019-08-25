from initialize_db import columns, rules
from insert_db import InsertDB
import pprint

def create_count_query(rfile=None):
    q = "SELECT count(repr) from rules where commented = 'False' AND "
    for a in columns:
        if 'attr_' in a:
            q += "{} ISNULL AND ".format(a)
    if rfile is None:
        q = q[:-5] + ';'
    else:
        q = q + "file = '{}';".format(rfile)
    return q

def count_query(rfilename,conn):
    cur = conn.cursor()
    cur.execute(create_count_query(rfile=rfilename))
    rows = cur.fetchall()
    return rows[0][0]

def print_active_rules_left(db="databases/test-snort-rules.db"):
    get_db = InsertDB(db)
    conn = get_db.create_connection()
    for r in rules:
        print count_query(r[0][:-6], conn)

def print_columns():
    pp = pprint.PrettyPrinter()
    pp.pprint(columns)

def create_attr_query(a):
    q = "SELECT count(repr) from rules where commented = 'False' AND "
    q += "{} = 'True'".format(a)
    return q

ts = []

def attr_query(conn):
    for c in columns:
        if 'attr_' not in c:
            continue
        cur = conn.cursor()
        cur.execute(create_attr_query(c))
        rows = cur.fetchall()
        ts.append((c,rows[0][0]))

get_db = InsertDB("databases/test-snort-rules.db")
conn = get_db.create_connection()

attr_query(conn)

sorted_list = sorted(ts, key=lambda x: x[1])

print sorted_list

#print create_count_query()
