export namespace main {
	
	export class AddRuleResponse {
	    success: boolean;
	    rule_id: number;
	    action: string;
	    app?: string;
	    ip?: string;
	    port?: number;
	
	    static createFrom(source: any = {}) {
	        return new AddRuleResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.rule_id = source["rule_id"];
	        this.action = source["action"];
	        this.app = source["app"];
	        this.ip = source["ip"];
	        this.port = source["port"];
	    }
	}
	export class DeleteRuleResponse {
	    success: boolean;
	    rule_id: number;
	
	    static createFrom(source: any = {}) {
	        return new DeleteRuleResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.success = source["success"];
	        this.rule_id = source["rule_id"];
	    }
	}
	export class Flow {
	    proto: number;
	    src: string;
	    dst: string;
	    bytes_sent: number;
	    bytes_recv: number;
	    pid: number;
	    proc: string;
	
	    static createFrom(source: any = {}) {
	        return new Flow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.proto = source["proto"];
	        this.src = source["src"];
	        this.dst = source["dst"];
	        this.bytes_sent = source["bytes_sent"];
	        this.bytes_recv = source["bytes_recv"];
	        this.pid = source["pid"];
	        this.proc = source["proc"];
	    }
	}
	export class FlowsResponse {
	    flow_count: number;
	    flows: Flow[];
	
	    static createFrom(source: any = {}) {
	        return new FlowsResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.flow_count = source["flow_count"];
	        this.flows = this.convertValues(source["flows"], Flow);
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
	export class Rule {
	    id: number;
	    action: string;
	    type: string;
	    dir: string;
	    value: string;
	    desc: string;
	
	    static createFrom(source: any = {}) {
	        return new Rule(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.action = source["action"];
	        this.type = source["type"];
	        this.dir = source["dir"];
	        this.value = source["value"];
	        this.desc = source["desc"];
	    }
	}
	export class RulesResponse {
	    rule_count: number;
	    rules: Rule[];
	
	    static createFrom(source: any = {}) {
	        return new RulesResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.rule_count = source["rule_count"];
	        this.rules = this.convertValues(source["rules"], Rule);
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
	export class StatusResponse {
	    service: string;
	    wfp_engine_active: boolean;
	    windivert_active: boolean;
	    active_rules: number;
	    active_flows: number;
	    rx_bytes_sec: number;
	    tx_bytes_sec: number;
	    total_rx_mb: number;
	    total_tx_mb: number;
	
	    static createFrom(source: any = {}) {
	        return new StatusResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.service = source["service"];
	        this.wfp_engine_active = source["wfp_engine_active"];
	        this.windivert_active = source["windivert_active"];
	        this.active_rules = source["active_rules"];
	        this.active_flows = source["active_flows"];
	        this.rx_bytes_sec = source["rx_bytes_sec"];
	        this.tx_bytes_sec = source["tx_bytes_sec"];
	        this.total_rx_mb = source["total_rx_mb"];
	        this.total_tx_mb = source["total_tx_mb"];
	    }
	}

}

