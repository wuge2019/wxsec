export namespace cross {
	
	export class HostStat {
	    host: string;
	    dynamicCount: number;
	    staticCount: number;
	    paths: number;
	    appIds: string[];
	    sdk: string;
	    encryptedOnly: boolean;
	
	    static createFrom(source: any = {}) {
	        return new HostStat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.dynamicCount = source["dynamicCount"];
	        this.staticCount = source["staticCount"];
	        this.paths = source["paths"];
	        this.appIds = source["appIds"];
	        this.sdk = source["sdk"];
	        this.encryptedOnly = source["encryptedOnly"];
	    }
	}
	export class Row {
	    key: string;
	    host: string;
	    path: string;
	    scheme: string;
	    category: string;
	    methods: string[];
	    statuses: number[];
	    queryKeys: string[];
	    appIds: string[];
	    staticFiles: string[];
	    staticCount: number;
	    dynamicCount: number;
	    sdk: string;
	    sample: string;
	    pattern: boolean;
	    notes: string[];
	
	    static createFrom(source: any = {}) {
	        return new Row(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.host = source["host"];
	        this.path = source["path"];
	        this.scheme = source["scheme"];
	        this.category = source["category"];
	        this.methods = source["methods"];
	        this.statuses = source["statuses"];
	        this.queryKeys = source["queryKeys"];
	        this.appIds = source["appIds"];
	        this.staticFiles = source["staticFiles"];
	        this.staticCount = source["staticCount"];
	        this.dynamicCount = source["dynamicCount"];
	        this.sdk = source["sdk"];
	        this.sample = source["sample"];
	        this.pattern = source["pattern"];
	        this.notes = source["notes"];
	    }
	}
	export class Report {
	    // Go type: time
	    generatedAt: any;
	    scanRoot: string;
	    flowTotal: number;
	    assetTotal: number;
	    rows: Row[];
	    hosts: HostStat[];
	    stats: Record<string, number>;
	    dynamicHosts: string[];
	    staticHosts: string[];
	
	    static createFrom(source: any = {}) {
	        return new Report(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.generatedAt = this.convertValues(source["generatedAt"], null);
	        this.scanRoot = source["scanRoot"];
	        this.flowTotal = source["flowTotal"];
	        this.assetTotal = source["assetTotal"];
	        this.rows = this.convertValues(source["rows"], Row);
	        this.hosts = this.convertValues(source["hosts"], HostStat);
	        this.stats = source["stats"];
	        this.dynamicHosts = source["dynamicHosts"];
	        this.staticHosts = source["staticHosts"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace decomp {
	
	export class Page {
	    bundle: string;
	    entry: string;
	    path: string;
	    kind: string;
	    bytes: number;
	
	    static createFrom(source: any = {}) {
	        return new Page(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.bundle = source["bundle"];
	        this.entry = source["entry"];
	        this.path = source["path"];
	        this.kind = source["kind"];
	        this.bytes = source["bytes"];
	    }
	}
	export class Result {
	    bundles: string[];
	    pages: Page[];
	    skipped: string[];
	    notes: string[];
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.bundles = source["bundles"];
	        this.pages = this.convertValues(source["pages"], Page);
	        this.skipped = source["skipped"];
	        this.notes = source["notes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class CAInfo {
	    path: string;
	    subject: string;
	    installed: boolean;
	    notAfter: string;
	    supported: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CAInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.subject = source["subject"];
	        this.installed = source["installed"];
	        this.notAfter = source["notAfter"];
	        this.supported = source["supported"];
	    }
	}
	export class CaptureOptions {
	    port: number;
	    intercept: boolean;
	    sysProxy: boolean;
	
	    static createFrom(source: any = {}) {
	        return new CaptureOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.port = source["port"];
	        this.intercept = source["intercept"];
	        this.sysProxy = source["sysProxy"];
	    }
	}
	export class CaptureStatus {
	    running: boolean;
	    addr: string;
	    port: number;
	    intercept: boolean;
	    flowCount: number;
	    dropped: number;
	    storePath: string;
	    caPath: string;
	    caInstalled: boolean;
	    caExpires: string;
	    sysProxy?: proxy.SysProxyState;
	    logs: string[];
	    scanReady: boolean;
	    scanRoot: string;
	    crossRows: number;
	    crossStats: Record<string, number>;
	
	    static createFrom(source: any = {}) {
	        return new CaptureStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.addr = source["addr"];
	        this.port = source["port"];
	        this.intercept = source["intercept"];
	        this.flowCount = source["flowCount"];
	        this.dropped = source["dropped"];
	        this.storePath = source["storePath"];
	        this.caPath = source["caPath"];
	        this.caInstalled = source["caInstalled"];
	        this.caExpires = source["caExpires"];
	        this.sysProxy = this.convertValues(source["sysProxy"], proxy.SysProxyState);
	        this.logs = source["logs"];
	        this.scanReady = source["scanReady"];
	        this.scanRoot = source["scanRoot"];
	        this.crossRows = source["crossRows"];
	        this.crossStats = source["crossStats"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class DirEntry {
	    name: string;
	    path: string;
	    isDir: boolean;
	    size: number;
	    ext: string;
	
	    static createFrom(source: any = {}) {
	        return new DirEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.isDir = source["isDir"];
	        this.size = source["size"];
	        this.ext = source["ext"];
	    }
	}
	export class SourceView {
	    path: string;
	    content: string;
	    lines: number;
	    truncated: boolean;
	    size: number;
	
	    static createFrom(source: any = {}) {
	        return new SourceView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.content = source["content"];
	        this.lines = source["lines"];
	        this.truncated = source["truncated"];
	        this.size = source["size"];
	    }
	}
	export class Task {
	    id: string;
	    kind: string;
	    title: string;
	    status: string;
	    message: string;
	    current: number;
	    total: number;
	    progress: number;
	    output: string;
	    restored: string;
	    error: string;
	
	    static createFrom(source: any = {}) {
	        return new Task(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.kind = source["kind"];
	        this.title = source["title"];
	        this.status = source["status"];
	        this.message = source["message"];
	        this.current = source["current"];
	        this.total = source["total"];
	        this.progress = source["progress"];
	        this.output = source["output"];
	        this.restored = source["restored"];
	        this.error = source["error"];
	    }
	}
	export class UnpackRequest {
	    source: string;
	    appId: string;
	    outDir: string;
	    beautify: boolean;
	    restore: boolean;
	    decompile: boolean;
	    scan: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UnpackRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.source = source["source"];
	        this.appId = source["appId"];
	        this.outDir = source["outDir"];
	        this.beautify = source["beautify"];
	        this.restore = source["restore"];
	        this.decompile = source["decompile"];
	        this.scan = source["scan"];
	    }
	}

}

export namespace proxy {
	
	export class Flow {
	    seq: number;
	    // Go type: time
	    time: any;
	    method: string;
	    url: string;
	    scheme: string;
	    host: string;
	    path: string;
	    query: string;
	    status: number;
	    proto: string;
	    reqType: string;
	    contentType: string;
	    reqBytes: number;
	    respBytes: number;
	    durationMs: number;
	    appId: string;
	    wxVersion: string;
	    referer: string;
	    userAgent: string;
	    intercepted: boolean;
	    note: string;
	
	    static createFrom(source: any = {}) {
	        return new Flow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.seq = source["seq"];
	        this.time = this.convertValues(source["time"], null);
	        this.method = source["method"];
	        this.url = source["url"];
	        this.scheme = source["scheme"];
	        this.host = source["host"];
	        this.path = source["path"];
	        this.query = source["query"];
	        this.status = source["status"];
	        this.proto = source["proto"];
	        this.reqType = source["reqType"];
	        this.contentType = source["contentType"];
	        this.reqBytes = source["reqBytes"];
	        this.respBytes = source["respBytes"];
	        this.durationMs = source["durationMs"];
	        this.appId = source["appId"];
	        this.wxVersion = source["wxVersion"];
	        this.referer = source["referer"];
	        this.userAgent = source["userAgent"];
	        this.intercepted = source["intercepted"];
	        this.note = source["note"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SysProxySnapshot {
	    enable: boolean;
	    server: string;
	    bypass: string;
	
	    static createFrom(source: any = {}) {
	        return new SysProxySnapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enable = source["enable"];
	        this.server = source["server"];
	        this.bypass = source["bypass"];
	    }
	}
	export class SysProxyState {
	    enabled: boolean;
	    server: string;
	    bypass: string;
	    managed: boolean;
	    managedAddr: string;
	    backupAt: string;
	    backup?: SysProxySnapshot;
	    backupPath: string;
	
	    static createFrom(source: any = {}) {
	        return new SysProxyState(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.enabled = source["enabled"];
	        this.server = source["server"];
	        this.bypass = source["bypass"];
	        this.managed = source["managed"];
	        this.managedAddr = source["managedAddr"];
	        this.backupAt = source["backupAt"];
	        this.backup = this.convertValues(source["backup"], SysProxySnapshot);
	        this.backupPath = source["backupPath"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace scanner {
	
	export class Asset {
	    url: string;
	    scheme: string;
	    host: string;
	    path: string;
	    file: string;
	    line: number;
	    count: number;
	    sdk: string;
	
	    static createFrom(source: any = {}) {
	        return new Asset(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.url = source["url"];
	        this.scheme = source["scheme"];
	        this.host = source["host"];
	        this.path = source["path"];
	        this.file = source["file"];
	        this.line = source["line"];
	        this.count = source["count"];
	        this.sdk = source["sdk"];
	    }
	}
	export class Finding {
	    id: string;
	    ruleId: string;
	    category: string;
	    title: string;
	    severity: string;
	    file: string;
	    line: number;
	    value: string;
	    context: string;
	    recommend: string;
	    occurrence: number;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.ruleId = source["ruleId"];
	        this.category = source["category"];
	        this.title = source["title"];
	        this.severity = source["severity"];
	        this.file = source["file"];
	        this.line = source["line"];
	        this.value = source["value"];
	        this.context = source["context"];
	        this.recommend = source["recommend"];
	        this.occurrence = source["occurrence"];
	    }
	}
	export class Result {
	    root: string;
	    // Go type: time
	    startedAt: any;
	    durationMs: number;
	    filesTotal: number;
	    filesScanned: number;
	    bytesScanned: number;
	    skipped: string[];
	    findings: Finding[];
	    assets: Asset[];
	    hosts: string[];
	    sdkAssets: Asset[];
	    sdkHosts: string[];
	    appInfo: Record<string, any>;
	    sevCount: Record<string, number>;
	
	    static createFrom(source: any = {}) {
	        return new Result(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.root = source["root"];
	        this.startedAt = this.convertValues(source["startedAt"], null);
	        this.durationMs = source["durationMs"];
	        this.filesTotal = source["filesTotal"];
	        this.filesScanned = source["filesScanned"];
	        this.bytesScanned = source["bytesScanned"];
	        this.skipped = source["skipped"];
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.assets = this.convertValues(source["assets"], Asset);
	        this.hosts = source["hosts"];
	        this.sdkAssets = this.convertValues(source["sdkAssets"], Asset);
	        this.sdkHosts = source["sdkHosts"];
	        this.appInfo = source["appInfo"];
	        this.sevCount = source["sevCount"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace wechat {
	
	export class CacheCleanup {
	    deleted: number;
	    files: number;
	    bytes: number;
	    failed: string[];
	
	    static createFrom(source: any = {}) {
	        return new CacheCleanup(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.deleted = source["deleted"];
	        this.files = source["files"];
	        this.bytes = source["bytes"];
	        this.failed = source["failed"];
	    }
	}
	export class CacheDir {
	    appId: string;
	    path: string;
	    dirs: string[];
	    files: number;
	    bytes: number;
	
	    static createFrom(source: any = {}) {
	        return new CacheDir(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.appId = source["appId"];
	        this.path = source["path"];
	        this.dirs = source["dirs"];
	        this.files = source["files"];
	        this.bytes = source["bytes"];
	    }
	}
	export class PackageRef {
	    appId: string;
	    versions: string[];
	    files: string[];
	    totalSize: number;
	    latestMod: number;
	    encrypted: boolean;
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new PackageRef(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.appId = source["appId"];
	        this.versions = source["versions"];
	        this.files = source["files"];
	        this.totalSize = source["totalSize"];
	        this.latestMod = source["latestMod"];
	        this.encrypted = source["encrypted"];
	        this.source = source["source"];
	    }
	}
	export class RootInfo {
	    path: string;
	    label: string;
	    exists: boolean;
	    note: string;
	
	    static createFrom(source: any = {}) {
	        return new RootInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.label = source["label"];
	        this.exists = source["exists"];
	        this.note = source["note"];
	    }
	}

}

export namespace wxapkg {
	
	export class Entry {
	    name: string;
	    offset: number;
	    size: number;
	
	    static createFrom(source: any = {}) {
	        return new Entry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.offset = source["offset"];
	        this.size = source["size"];
	    }
	}

}

