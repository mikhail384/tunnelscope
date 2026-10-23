import contextlib
import collections
import pathlib
import json
import sqlite3
import threading
import time
from .common import domain, ip


SCHEMA = '''
CREATE TABLE IF NOT EXISTS clients(id TEXT PRIMARY KEY, source TEXT, label TEXT, ips TEXT, up INTEGER, down INTEGER, last_seen REAL, updated REAL);
CREATE TABLE IF NOT EXISTS usage(client_id TEXT, bucket INTEGER, up INTEGER, down INTEGER, PRIMARY KEY(client_id,bucket));
CREATE TABLE IF NOT EXISTS flows(id TEXT PRIMARY KEY, client_id TEXT, source TEXT, destination TEXT, port INTEGER, protocol TEXT, domain TEXT, evidence TEXT, first_seen REAL, last_seen REAL, up INTEGER, down INTEGER, packets INTEGER, measurement TEXT);
CREATE INDEX IF NOT EXISTS flows_recent ON flows(last_seen);
CREATE INDEX IF NOT EXISTS flows_client ON flows(client_id,last_seen);
CREATE INDEX IF NOT EXISTS flows_source_recent ON flows(source,last_seen);
CREATE INDEX IF NOT EXISTS usage_bucket ON usage(bucket,client_id);
CREATE TABLE IF NOT EXISTS owners(ip TEXT PRIMARY KEY, asn TEXT, holder TEXT, prefix TEXT, updated REAL, error TEXT);
CREATE TABLE IF NOT EXISTS status(source TEXT PRIMARY KEY, updated REAL, payload TEXT);
CREATE TABLE IF NOT EXISTS receipts(id TEXT PRIMARY KEY, created REAL);
CREATE TABLE IF NOT EXISTS aliases(client_id TEXT PRIMARY KEY, label TEXT);
'''


class Store:
    def __init__(self, path):
        self.path=str(path)
        self.summary_lock=threading.Lock();self.summary_compute=threading.Lock();self.summaries=collections.OrderedDict();self.pending=set();self.summary_epoch=0
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=10)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=NORMAL')
        self.db.executescript(SCHEMA)
        self.db.commit()

    def ingest(self, batch):
        now = time.time()
        with self.lock, self.db:
            if self.db.execute('SELECT 1 FROM receipts WHERE id=?', (batch['id'],)).fetchone():
                return
            for c in batch.get('clients', [])[:5000]:
                old = self.db.execute('SELECT up,down FROM clients WHERE id=?', (c['id'],)).fetchone()
                up, down = max(0, int(c.get('up', 0))), max(0, int(c.get('down', 0)))
                if old:
                    # First sample establishes baseline. A reset never bills historical usage.
                    du = max(0, up - old['up']) if up >= old['up'] else up
                    dd = max(0, down - old['down']) if down >= old['down'] else down
                    self.db.execute('INSERT INTO usage VALUES(?,?,?,?) ON CONFLICT(client_id,bucket) DO UPDATE SET up=up+excluded.up,down=down+excluded.down',
                                    (c['id'], int(now // 300) * 300, du, dd))
                self.db.execute('INSERT INTO clients VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET label=excluded.label,ips=excluded.ips,up=excluded.up,down=excluded.down,last_seen=excluded.last_seen,updated=excluded.updated',
                                (c['id'], c['source'], str(c['label'])[:200], json.dumps(c.get('ips', [])[:100]), up, down, float(c.get('last_seen', 0)), now))
            for f in batch.get('flows', [])[:10000]:
                # No payload or credentials enter this store. Domains are evidence, not browser history.
                dest = ip(f.get('destination', '')) or domain(f.get('destination', ''))
                if not dest:
                    continue
                self.db.execute('INSERT INTO flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET domain=CASE WHEN excluded.domain<>\'\' THEN excluded.domain ELSE flows.domain END,evidence=CASE WHEN excluded.domain<>\'\' THEN excluded.evidence ELSE flows.evidence END,last_seen=MAX(flows.last_seen,excluded.last_seen),up=flows.up+excluded.up,down=flows.down+excluded.down,packets=flows.packets+excluded.packets',
                                (f['id'], f.get('client_id', ''), f['source'], dest, int(f.get('port', 0)), str(f.get('protocol', ''))[:20], domain(f.get('domain', '')), str(f.get('evidence', 'IP'))[:80], float(f.get('first_seen', now)), float(f.get('last_seen', now)), max(0,int(f.get('up', 0))), max(0,int(f.get('down', 0))), max(0,int(f.get('packets', 0))), f.get('measurement', 'observed')))
            for s in batch.get('status', []):
                self.db.execute('INSERT OR REPLACE INTO status VALUES(?,?,?)', (s['source'], now, json.dumps(s, ensure_ascii=False)))
            self.db.execute('INSERT INTO receipts VALUES(?,?)', (batch['id'], now))

    def cleanup(self, days=14):
        cutoff = time.time() - days * 86400
        with self.lock, self.db:
            self.db.execute('DELETE FROM flows WHERE last_seen<?', (cutoff,))
            self.db.execute('DELETE FROM usage WHERE bucket<?', (cutoff,))
            self.db.execute('DELETE FROM receipts WHERE created<?', (time.time() - 86400,))
            self.db.execute('DELETE FROM flows WHERE id IN (SELECT id FROM flows ORDER BY last_seen DESC LIMIT -1 OFFSET 100000)')

    def owner(self, addr):
        with self.lock:
            r = self.db.execute('SELECT * FROM owners WHERE ip=?', (addr,)).fetchone()
            return dict(r) if r else None

    def set_owner(self, row):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO owners VALUES(?,?,?,?,?,?)', (row['ip'], row.get('asn',''), row.get('holder',''), row.get('prefix',''), time.time(), row.get('error','')))

    @contextlib.contextmanager
    def reader(self):
        # WAL readers never hold the collector's write lock during aggregation.
        db=sqlite3.connect(pathlib.Path(self.path).resolve().as_uri()+'?mode=ro',uri=True,timeout=10)
        db.row_factory=sqlite3.Row
        try:
            db.execute('PRAGMA query_only=ON');db.execute('PRAGMA cache_size=-2048');db.execute('BEGIN')
            yield db
        finally:db.close()

    def rename(self,cid,label):
        with self.lock,self.db:
            if not self.db.execute('SELECT 1 FROM clients WHERE id=?',(cid,)).fetchone():return False
            self.db.execute('INSERT OR REPLACE INTO aliases VALUES(?,?)',(cid,label))
        with self.summary_lock:self.summaries.clear();self.summary_epoch+=1
        return True

    def snapshot(self, hours=24, client='', search='', source='', limit=300, fresh=False, background=False):
        cutoff = time.time() - hours * 3600
        where, args = ['f.last_seen>=?'], [cutoff]
        if client:
            where.append('f.client_id=?'); args.append(client)
        if source:
            where.append('f.source=?'); args.append(source)
        if search:
            where.append('(f.domain LIKE ? OR f.destination LIKE ? OR o.holder LIKE ? OR c.label LIKE ? OR a.label LIKE ?)')
            args.extend(['%' + search[:100] + '%'] * 5)
        condition = ' AND '.join(where)
        joins = ' FROM flows f LEFT JOIN clients c ON c.id=f.client_id LEFT JOIN aliases a ON a.client_id=c.id LEFT JOIN owners o ON o.ip=f.destination '
        with self.reader() as db:
            clients = [dict(r) for r in db.execute('SELECT c.*, COALESCE(a.label,c.label) AS display_name,COALESCE(u.up,0) AS period_up,COALESCE(u.down,0) AS period_down FROM clients c LEFT JOIN aliases a ON a.client_id=c.id LEFT JOIN (SELECT client_id,SUM(up) up,SUM(down) down FROM usage WHERE bucket>=? GROUP BY client_id) u ON u.client_id=c.id ORDER BY period_up+period_down DESC,c.label', (cutoff,))]
            # Limit before enriching rows with labels/owners. Search retains all joins.
            fields="SELECT f.*,COALESCE(a.label,c.label,'Без привязки к клиенту') client_label,o.asn,o.holder,o.prefix,o.error AS owner_error"
            if search:
                sql=fields+joins+'WHERE '+condition+' ORDER BY f.last_seen DESC LIMIT ?'
            else:
                sql=fields+' FROM (SELECT * FROM flows f WHERE '+condition+' ORDER BY f.last_seen DESC LIMIT ?) f LEFT JOIN clients c ON c.id=f.client_id LEFT JOIN aliases a ON a.client_id=c.id LEFT JOIN owners o ON o.ip=f.destination ORDER BY f.last_seen DESC'
            rows=[dict(r) for r in db.execute(sql,args+[limit])]
            chart_args = [cutoff] + ([client] if client else [])
            chart = [dict(r) for r in db.execute('SELECT (bucket/3600)*3600 AS ts,SUM(up) up,SUM(down) down FROM usage WHERE bucket>=?' + (' AND client_id=?' if client else '') + ' GROUP BY ts ORDER BY ts', chart_args)]
            status = [dict(r) for r in db.execute('SELECT * FROM status')]
            usage = dict(db.execute('SELECT COALESCE(SUM(up),0) up,COALESCE(SUM(down),0) down FROM usage WHERE bucket>=?' + (' AND client_id=?' if client else ''), chart_args).fetchone())
            key=(hours,client,search[:100],source)
            summary_pending=False
            with self.summary_lock:cached=self.summaries.get(key)
            expired=not cached or time.monotonic()-cached[0]>=20
            if background and not fresh and expired:
                summary_pending=True
                with self.summary_lock:
                    if key not in self.pending and len(self.pending)<8:
                        self.pending.add(key)
                        threading.Thread(target=self.refresh_summary,args=(key,condition,list(args),bool(search),self.summary_epoch),daemon=True,name='history-summary').start()
            elif fresh or expired:
                totals,top=self.aggregate(db,condition,args,bool(search))
                cached=(time.monotonic(),time.time(),totals,top)
                with self.summary_lock:self.cache_summary(key,cached)
            if cached:summary_updated,totals,top=cached[1:]
            else:summary_updated,totals,top=0,{'connections':None,'domains':None,'observed_up':None,'observed_down':None},[]
        for c in clients:
            c['ips'] = json.loads(c['ips'])
        for s in status:
            s['details'] = json.loads(s.pop('payload'))
        return {'now':time.time(), 'hours':hours, 'summary_updated':summary_updated, 'summary_pending':summary_pending, 'clients':clients, 'flows':rows, 'totals':totals, 'usage':usage, 'chart':chart, 'status':status, 'top':top}

    def cache_summary(self,key,value):
        self.summaries[key]=value;self.summaries.move_to_end(key)
        while len(self.summaries)>8:self.summaries.popitem(last=False)

    @staticmethod
    def aggregate(db,condition,args,search):
        joins=' FROM flows f LEFT JOIN clients c ON c.id=f.client_id LEFT JOIN aliases a ON a.client_id=c.id LEFT JOIN owners o ON o.ip=f.destination '
        total_from=joins if search else ' FROM flows f '
        top_from=joins if search else ' FROM flows f LEFT JOIN owners o ON o.ip=f.destination '
        totals=dict(db.execute("SELECT COUNT(*) connections,COUNT(DISTINCT CASE WHEN f.domain<>'' THEN f.domain END) domains,COALESCE(SUM(f.up),0) observed_up,COALESCE(SUM(f.down),0) observed_down"+total_from+'WHERE '+condition,args).fetchone())
        top=[dict(r) for r in db.execute("SELECT COALESCE(NULLIF(f.domain,''),f.destination) name,MAX(o.holder) holder,SUM(f.up+f.down) bytes,COUNT(*) connections"+top_from+'WHERE '+condition+' GROUP BY name ORDER BY bytes DESC,connections DESC LIMIT 8',args)]
        return totals,top

    def refresh_summary(self,key,condition,args,search,epoch):
        try:
            with self.summary_compute,self.reader() as db:
                totals,top=self.aggregate(db,condition,args,search)
            with self.summary_lock:
                if epoch==self.summary_epoch:self.cache_summary(key,(time.monotonic(),time.time(),totals,top))
        except sqlite3.Error:
            # The next request retries; do not return fabricated counts on failure.
            pass
        finally:
            with self.summary_lock:self.pending.discard(key)
