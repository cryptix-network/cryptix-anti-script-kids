const path = require('path');
const crypto = require('crypto');
const EventEmitter = require("events");
const FlowRouter = require('@aspectron/flow-router');
const utils = require('@aspectron/flow-utils');
const async = require('@aspectron/flow-async');
//require("colors");
const fs = require("fs");
const args = utils.args();
const sockjs = require('sockjs');
const session = require('express-session');
const express = require('express');
const bodyParser = require('body-parser');
const Cookie = require("cookie");
const CookieSignature = require("cookie-signature");
const { Command, CommanderError } = require('commander');
const ws = require('ws');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');
const fetch = require('node-fetch');
const querystring = require('querystring');
const Decimal = require('decimal.js');
const pLimit = require('p-limit');
//const child_process = require("node:child_process");
let lastTs = Date.now()/1000;
let timeDiffDumpCount = 0;

setInterval(()=>{
	let ts = Date.now()/1000;
	let diff = ts - lastTs;
	if (diff > 2){
		console.log("########### time-tick-diff ########### >>>>:".red, diff);
	}else{
		timeDiffDumpCount++;
		if (timeDiffDumpCount % 10 == 0){
			timeDiffDumpCount = 0;
			//console.log("======== time-tick-diff =====:".green, diff);
		}
	}
	lastTs = ts;
}, 1000)

const {FlowHttp} = require('@aspectron/flow-http')({
	express,
	session,
	//sockjs,
	ws,
	Cookie,
	CookieSignature,
	grpc, protoLoader
});
const { Wallet, initCryptixFramework, log } = require('@cryptix/wallet-worker');
const { RPC } = require('@cryptix/grpc-node');
const { dpc } = require('@cryptix/wallet/dist/utils/helper');

class CryptixPWA extends EventEmitter {
	constructor(appFolder){
		super();
		this.appFolder = appFolder;
		this.config = utils.getConfig(path.join(appFolder, "config", "cryptix-wallet-pwa"));
		this.ip_limit_map = new Map();
		this.cache = { };

		if(this.config.cf?.token) {
			const { token } = this.config.cf;
			this.CF = require('cloudflare')({ token });
		}

		this.options = {
			port : 3080
		}

		if(!this.config?.http?.session) {

			console.log('');
			console.log('_  _ _ ____ ____ _ _  _ ____    ____ ____ ____ ____ _ ____ _  _    ');
			console.log('|\\/| | [__  [__  | |\\ | | __    [__  |___ [__  [__  | |  | |\\ |  ');
			console.log('|  | | ___] ___] | | \\| |__]    ___] |___ ___] ___] | |__| | \\|    ');

			this.http_session_ = {
				secret:"34343546756767567657534578678672346573237436523798",
				key:"cryptix-faucet-pwa"
			};
		}else{
			this.http_session_ = this.config.http.session;
		}

		console.log('_________                        __  .__        ');
		console.log('\\_   ___ \\_______ ___.__._______/  |_|__|__  ___');
		console.log('/    \\  \\/\\_  __ <   |  |\\____ \\   __\\  \\  \\/  /');
		console.log('\\     \\____|  | \\/\\___  ||  |_> >  | |  | >    < ');
		console.log(' \\______  /|__|   / ____||   __/|__| |__/__/\\_ \\');
		console.log('        \\/        \\/     |__|                 \\/');
		

		Wallet.setWorkerLogLevel("none");
	}

	async initHttp(){

		const { host, port } = this.options;

		const flowHttp = this.flowHttp = new FlowHttp(__dirname, {
			config:{
				websocketMode:"RPC",
				websocketPath:"/rpc",
				certificates:{
					key: './certificates/pwa.key',
					crt: './certificates/pwa.crt'
				},
				http:Object.assign({
					host,
					port,
					session: this.http_session_,
					ssl : false
				}, this.config?.http||{}),
				staticFiles:{
					//'/':'http',
					'/dist':'dist'
				},
				grpc: {
					protoPath: path.join(this.appFolder, "node_modules/@cryptix/grpc/proto/messages.proto"),
					server: this.grpc.host,
					packageKey: "protowire",
					options: {
					  "grpc.max_receive_message_length": -1,  
					  "grpc.max_connection_idle_ms": 600000,  
					},
					clientWaitTime: 120000
				  }
			}
		});
		// this.flowHttp = flowHttp;

		flowHttp.on("app.init", async (args)=>{
			let {app} = args;
			app.use(bodyParser.json())
			app.use(bodyParser.urlencoded({ extended: true }))

			let rootFolder = this.appFolder;
			let config = this.config||{};
			const {folders={}} = config;
			const {
				cryptixUX='/node_modules/@cryptix/ux',
				flowUX='/node_modules/@aspectron/flow-ux',
				walletWorker='/node_modules/@cryptix/wallet-worker',
				secp256k1='/node_modules/secp256k1-wasm/http',
				grpcWeb='/node_modules/@cryptix/grpc-web',
				flowGRPCWeb='/node_modules/@aspectron/flow-grpc-web',
				cryptixCoreLib='/node_modules/@cryptix/core-lib'
			} = folders;

			app.use([
				"/send/:a?", "/qrscanner/:a?", "/open/:a?",
				"/faucet/:a?", "/seeds/:a?", "/receive/:a?", "/t9/:a?"], (req, res)=>{
				res.redirect("/")
			})

			// console.log("walletWorker", walletWorker);
			const files = [
				'./',
				flowUX,cryptixUX,grpcWeb,
				'/node_modules/@cryptix/wallet',
				'/node_modules/@cryptix/grpc',
				cryptixCoreLib
			].map(v=>path.join(__dirname,v,'package.json'));

			const indexFile = path.join(__dirname,'http','index.html');
			let indexHtml='';
			const updateIndex = () => {
				return new Promise((resolve) => {
					this.purgeCache();
					try {
						let list = files.map(f=>{
							let {version,name} = JSON.parse(fs.readFileSync(f,'utf8'));
							console.log(`[version]: (${version}) for: ${f}`);
							return {version,name};
						});
						let hash = crypto.createHash('sha256').update(list.map(info=>info.version).join('')).digest('hex').substring(0,16);
						fs.writeFileSync(".script-hash", hash);
						let script = `\n\t<script>\n\t\twindow.PWA_MODULES={};\n\t\t${list.map(i=>`window.PWA_MODULES["${i.name}"] = "${i.version}";`).join('\n\t\t')}\n\t</script>`;
						fs.readFile(indexFile,{encoding:'utf-8'}, (err, data)=>{
							if(err)
								return log.error(err);
							indexHtml = data.replace(
								`<script type="module" src="/dist/wallet-app.js"></script>`,
								`\n${script}\n\t<script type="module" src="/dist/wallet-app.js?v=${hash}"></script>`);
							indexHtml = indexHtml.replace('ident:"cryptix:ident"', `ident:"${hash}"`);
							//console.log(indexHtml);
							resolve();
						})
					} catch(ex) {
						log.error('updateIndex',ex);
					}
				});
			}
			await updateIndex();
			files.forEach(f=>fs.watch(f,updateIndex));
			fs.watch(indexFile,updateIndex);
			app.get(['/','/index.html'], (req,res) => {
				res.send(indexHtml);
			})

			//cryptix-wallet-worker/worker.js
			app.use('/resources', express.static( path.join(cryptixUX, "resources"), {
				index: 'false'
			}))
			app.use('/', express.static( path.join(rootFolder, "http"), {
				index: 'false'
			}))
			app.use('/', express.static( path.join(rootFolder, "dist"), {
				index: 'false'
			}))
			app.get('/api/health', async (req, res)=>{
				let info = null;
				let status = 200;
				let session = req.session;
				let tsDiff = (Date.now() - (session.healthResTs || 0))/1000;
				session.healthResTs = Date.now();
				let isConnected = this.grpc.cryptixd.client.isConnected;
				if (tsDiff < 20){
					res.status(504).send(JSON.stringify({code:"PLEASE-WAIT-20-SEC-FOR-BLOCK-INFO-REQUEST", isConnected}))
					return
				}

				info = await this.grpc.cryptixd.request('getInfoRequest')
					.then(i=>{
						if (!i?.isSynced){
							status = 502;
						}
						return i;
					})
				.catch((e)=>{
					if ((e+"").includes("not connected")){
						status = 500;
						isConnected = false;
					}
				});
				res.status(status).send(JSON.stringify({info, isConnected}))
			})
			app.get('/cryptix-wallet-worker/worker.js', (req, res)=>{
				res.sendFile(path.join(rootFolder, 'dist/cryptix-wallet-worker-core.js'))
			})
			app.get('/node_modules/@aspectron/flow-grpc-web/flow-grpc-web.js', (req, res)=>{
				res.redirect('/node_modules/@aspectron/flow-grpc-web/lib/flow-grpc-web.js')
			})
			app.get('(/cryptix-wallet-worker)?/secp256k1.wasm', (req, res)=>{
				res.setHeader("Content-Type", "application/wasm")
				let file = path.join(rootFolder, secp256k1, 'secp256k1.wasm');
				let stream = fs.createReadStream(file);
				// This will wait until we know the readable stream is actually valid before piping
				stream.on('open', function () {
					// This just pipes the read stream to the response object (which goes to the client)
					stream.pipe(res);
				});
				//stream.pipe(res)
				//res.sendFile(file)
			})

			let router = new FlowRouter(app, {
				mount:{

					flowUX:"/flow/flow-ux",
					litHtml:'/lit-html',
					litElement:'/lit-element',
					webcomponents:'/webcomponentsjs',
					sockjs:'/sockjs'
				},
				rootFolder,
				folders:[
					{url:'/http', folder:path.join(rootFolder, "http")},
					{url:'/cryptix-ux', folder:cryptixUX},
					{url:'/node_modules/@aspectron/flow-ux', folder:flowUX},
					{url:'/cryptix-wallet-worker', folder:walletWorker},
					{url:'/resources/extern', folder:flowUX+'/resources/extern'},
					{url:'/@cryptix/grpc-web', folder:grpcWeb},
					{url:'/node_modules/@aspectron/flow-grpc-web', folder:flowGRPCWeb},
					{url:'/flow-qrscanner', folder:'../flow-qrscanner'}
				]
			});
			router.init();
		});

		flowHttp.init();
	}

	
	async initCryptix() {
		await initCryptixFramework();
	
		const aliases = Object.keys(Wallet.networkAliases);
		let filter = aliases.map((alias) => this.options[alias] ? Wallet.networkAliases[alias] : null).filter(v => v);
	
		if (this.options.grpc && filter.length !== 1) {
			log.error('You must explicitly use the network flag when specifying the gRPC option');
			log.error('Option required: --mainnet, --testnet, --devnet, --simnet');
			process.exit(1);
		}
	
		let network = filter.shift() || 'cryptix';
		let port = Wallet.networkTypes[network].port;
		let host = this.options.grpc || `127.0.0.1:${port}`;
	
		console.log(`Creating gRPC binding for network '${network}' at ${host}`);
		log.info(`Creating gRPC binding for network '${network}' at ${host}`);
	
		const cryptixd = new RPC({ clientConfig: { host } });
		cryptixd.onError((error) => log.error(`gRPC[${host}] ${error}`));
	
		cryptixd.onConnect(async () => {
			try {
				let res = await this.getUtxosWithQueue([]);
				let { error } = res;
	
				this.grpc.flags.utxoIndex = !error?.message?.includes('--utxoindex');
				this.emit("grpc.flags", this.grpc.flags);
				log.info("grpc.flags:", this.grpc.flags, 'getUtxosByAddresses:test:', res);
			} catch (err) {
				log.error("gRPC Request Failed:", err);
			}
		});
	
		this.grpc = { network, port, host, cryptixd, flags: {} };
	}
	
	limit = pLimit(1000);
	
	async getUtxosWithQueue(addresses) {
		return this.limit(() => this.grpc.cryptixd.getUtxosByAddresses(addresses));
	}
	
	monitorLimit = pLimit(1000);
	
	async initMonitors() {
		const medianOffset = 45 * 1000; 
		const medianShift = Math.ceil(263 * 0.5 * 1000);
		this.monitors = { pollingActive: false, activeRequests: new Set() }; 
	
		const poll = async () => {
			if (this.monitors.pollingActive) {
				console.log("WARNING: Polling already active, skip new poll...");
				return;
			}
			this.monitors.pollingActive = true;
	

			if (this.monitors.activeRequests.size >= 25) {
				console.log("WARNING: Too many parallel requests, polling paused...");
				this.monitors.pollingActive = false;
				setTimeout(poll, 3500);
				return;
			}
	
			let request;
			request = this.monitorLimit(async () => {
				this.monitors.activeRequests.add(request); 
				try {
					if (!this.grpc.cryptixd.client.isConnected) return;
	
					const ts_ = new Date();
					const ts = ts_.getTime() - medianShift;
	
					const bdi = await this.grpc.cryptixd.request('getBlockDagInfoRequest');
					const vspbs = await this.grpc.cryptixd.request('getVirtualSelectedParentBlueScoreRequest');
	
					const blueScore = parseInt(vspbs.blueScore);
					const blockCount = parseInt(bdi.blockCount);
					const headerCount = parseInt(bdi.headerCount);
					const difficulty = parseInt(bdi.difficulty);
					const networkName = bdi.networkName;
					const pastMedianTime = parseInt(bdi.pastMedianTime);
					const pastMedianTimeDiff = Math.max(ts - pastMedianTime, 0);
	

					const payload = {
						blueScore, blockCount, headerCount, difficulty, networkName, pastMedianTime, pastMedianTimeDiff
					};
	

					checkPayloadSize(payload);
	
					this.flowHttp.sockets.publish('network-status', payload);
				} catch (ex) {
					console.log("Fehler bei Monitor-Request:", ex.toString());
				} finally {
					this.monitors.activeRequests.delete(request); 
				}
			});
	
			await request; 
	
			this.monitors.pollingActive = false; 
			setTimeout(poll, 3500);
		};
	
		poll();
	}
	
	

	/**
	* @return {String} 
	*/
	getI18nFilePath(name){
		return path.join(this.appFolder, name);
	}

	/**
	* @return {Array} 
	*/
	getI18nEntries(){
		let localEntries = this._getI18nEntries('i18n.entries');
		let dataEntries = this._getI18nEntries('i18n.data');
		if(!dataEntries.length)
			return localEntries;
		let localEntriesMap = this.createI18nEntriesMap(localEntries);
		let dataEntriesMap = this.createI18nEntriesMap(dataEntries);
		return Object.values(Object.assign(localEntriesMap, dataEntriesMap))
	}
	createI18nEntriesMap(entries){
		let map = {}
		entries.forEach(e=>{
			if(!e.en)
				return
			map[e.en] = e;
		});

		return map;
	}
	_getI18nEntries(fileName){
		let dataFile = this.getI18nFilePath(fileName);
		if(!fs.existsSync(dataFile))
			return [];

		let data = (fs.readFileSync(dataFile)+"").trim();
		if(!data.length)
			return [];
		try{
			data = JSON.parse(data);
		}catch(e){
			return [];
		}

		return data || [];
	}

	async initRPC() {
		const { flowHttp } = this;
		let k = ()=> (Math.random()*100).toFixed(0);
		let randomIP = `${k()}.${k()}.${k()}.${k()}`
		const faucetUrl = 'https://faucet.cryptix-network.org';
		
		let i18nEntries = this.getI18nEntries();
		const pLimit = require('p-limit');
		const wsLimit = pLimit(1000); 
		
		let i18nRequests = flowHttp.sockets.subscribe("get-app-i18n-entries");
		(async () => {
			for await (const msg of i18nRequests) {
				await wsLimit(() => msg.respond({ entries: i18nEntries })); 
			}
		})();

		let activeClients = new Set();
		const MAX_CLIENTS = 1000;
		
		let networkRequests = flowHttp.sockets.subscribe("get-network");
		
		(async () => {
			for await (const msg of networkRequests) {
				if (activeClients.size >= MAX_CLIENTS) {
					console.log("Too many clients connected, request rejected:", msg.id);
					continue; 
				}
		

				activeClients.add(msg.id);
				msg.respond({ network: this.grpc.network });
		
				msg.socket.on("close", () => {
					activeClients.delete(msg.id);
					console.log(`Client ${msg.id} closed the connection and was removed.`);
				});
			}
		})();

		/*
		let getRequests = flowHttp.sockets.subscribe("faucet-request");
		(async ()=>{
			for await(const msg of getRequests) {
				let { data, ip } = msg;
				//ip = randomIP;
				const { address, amount } = data;
				fetch(`${faucetUrl}/api/${this.config.faucet_apikey}/get/${address}?ip=${querystring.escape(ip)}&amount=${querystring.escape(amount)}`, { method: 'GET' })
				.then(res => res.json()) 
				.then(json => msg.respond({ip, ...json}))
				.catch(ex=>{
					msg.respond({error:'Unable to request funds from faucet'});
					console.log(ex.toString());
				});
			}
		})();
		let availableRequests = flowHttp.sockets.subscribe("faucet-available");
		(async ()=>{
			for await(const msg of availableRequests) {
				let { data, ip } = msg;
				const { address } = data;
				//ip = randomIP;
				fetch(`${faucetUrl}/api/${this.config.faucet_apikey}/available/${address}?ip=${querystring.escape(ip)}`, { method: 'GET' })
				.then(res => res.json()) 
				.then(json => msg.respond({ip, ...json}))
				.catch(ex=>{
					msg.respond({error:'Unable to obtain faucet balance'});
					console.log(ex.toString());
				});
			}
		})();
		*/
	}

	purgeCache() {
        if(!this.CF)
			return;
		if(this._cf_purge)
			clearTimeout(this._cf_purge);
		this._cf_purge = setTimeout(()=>{
			delete this._cf_purge;
			this.purgeCache_();
		}, 5000);
	}

    purgeCache_() {
        if(!this.CF)
			return;
		const { zone, purge } = this.config.cf;
		if(!zone || !purge) {
			log.error(`CF - please configure cloudflare 'zone' and 'purge' settings!`);
			return;
		}

		log.warn('CF purging cache zone',this.config.cf.zone);
        this.CF.zones.purgeCache(zone, purge).then((data) => {
			log.warn(`Cloudflare cache purged`);
          // console.log(`Callback:`, data);
        }, (error) => {
			log.error('Error purging cloudflare cache -',error);
        });
    }

	async main() {
		const logLevels = ['error','warn','info','verbose','debug'];
		const program = this.program = new Command();
		program
			.version('0.0.1', '--version')
			.description('Cryptix Node Wallet')
			.helpOption('--help','display help for command')
			.option('--log <level>',`set log level ${logLevels.join(', ')}`, (level)=>{
				if(!logLevels.includes(level))
					throw new Error(`Log level must be one of: ${logLevels.join(', ')}`);
				return level;
			})
			.option('--restart-after <seconds>','auto kill after', false)
			.option('--verbose','log wallet activity')
			.option('--debug','debug wallet activity')
			.option('--testnet','use testnet network')
			.option('--devnet','use devnet network')
			.option('--simnet','use simnet network')
			.option('--mainnet','use cryptix/mainnet network')
			//.option('--no-ssl','disable SSL')
			.option('--host <host>','http host (default: localhost)', 'localhost')
			.option('--port <port>',`set http port (default ${this.options.port})`, (port)=>{
				port = parseInt(port);
				if(isNaN(port))
					throw new Error('Port is not a number');
				if(port < 0 || port > 0xffff)
					throw new Error('Port number is out of range');
				return port;
			})
            .option('--grpc <address>','use custom gRPC address <host:port>')
			;

		program.command('run', { isDefault : true })
			.description('run wallet daemon')
			.action(async ()=>{

				let options = program.opts();
				Object.entries(options).forEach(([k,v])=>{ if(v === undefined) delete options[k]; })
				Object.assign(this.options, options);
				//  console.log(this.options);
				//  return;

				log.level = (this.options.verbose&&'verbose')||(this.options.debug&&'debug')||(this.options.log)||'info';

				await this.initCryptix();
				await this.initHttp();
				await this.initRPC();
				await this.initMonitors();
				//await this.initWallet();
				if(this.options.restartAfter){
					let seconds = parseInt(this.options.restartAfter, 0);
					console.log(`restarting in ${seconds} seconds....`)

					setTimeout(async ()=>{
						console.log("::::RESTART::::")
						process.exit(0);
						//cryptixPWA.flowHttp.server.close(()=>{
						//	process.exit("RESTART");
						//});
					}, seconds * 1000)
				}
				
			})

		program.parse();
	}

	CYTX(v) {
		var [int,frac] = Decimal(v).mul(1e-8).toFixed(8).split('.');
		int = int.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
		frac = frac?.replace(/0+$/,'');
		return frac ? `${int}.${frac}` : int;
	}

}

(async () => {
	let cryptixPWA = new CryptixPWA(__dirname);
	try {
		await cryptixPWA.main();
	} catch(ex) {
		console.log(ex.toString());
	}
})();


/*
process.on('exit', (code) => {
	if(code != 'RESTART')
		return
	//console.log("exit-code:"+code)
	child_process.execSync("node pwa");
})
*/


function checkPayloadSize(payload) {
    const maxSize = 800 * 1024; // 800 KB
    const payloadSize = Buffer.byteLength(JSON.stringify(payload)); 
    if (payloadSize > maxSize) {
        throw new Error('Payload exceeds the maximum allowed size of 800 KB');
    }
    return true;
}

