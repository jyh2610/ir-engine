function getName(e){return e.name}function queryKey(e){for(var t=[],n=0;n<e.length;n++){var o=e[n];if("object"==typeof o){var s="not"===o.operator?"!":o.operator;t.push(s+getName(o.Component))}else t.push(getName(o))}return t.sort().join("-")}const hasWindow="undefined"!=typeof window,now=hasWindow&&void 0!==window.performance?performance.now.bind(performance):Date.now.bind(Date);class EventDispatcher{constructor(){this._listeners={},this.stats={fired:0,handled:0}}addEventListener(e,t){let n=this._listeners;void 0===n[e]&&(n[e]=[]),-1===n[e].indexOf(t)&&n[e].push(t)}hasEventListener(e,t){return void 0!==this._listeners[e]&&-1!==this._listeners[e].indexOf(t)}removeEventListener(e,t){var n=this._listeners[e];if(void 0!==n){var o=n.indexOf(t);-1!==o&&n.splice(o,1)}}dispatchEvent(e,t,n){this.stats.fired++;var o=this._listeners[e];if(void 0!==o)for(var s=o.slice(0),r=0;r<s.length;r++)s[r].call(this,t,n)}resetCounters(){this.stats.fired=this.stats.handled=0}}class Query{constructor(e,t){if(this.Components=[],this.NotComponents=[],e.forEach(e=>{"object"==typeof e?this.NotComponents.push(e.Component):this.Components.push(e)}),0===this.Components.length)throw new Error("Can't create a query without components");this.entities=[],this.eventDispatcher=new EventDispatcher,this.reactive=!1,this.key=queryKey(e);for(var n=0;n<t._entities.length;n++){var o=t._entities[n];this.match(o)&&(o.queries.push(this),this.entities.push(o))}}addEntity(e){e.queries.push(this),this.entities.push(e),this.eventDispatcher.dispatchEvent(Query.prototype.ENTITY_ADDED,e)}removeEntity(e){let t=this.entities.indexOf(e);~t&&(this.entities.splice(t,1),t=e.queries.indexOf(this),e.queries.splice(t,1),this.eventDispatcher.dispatchEvent(Query.prototype.ENTITY_REMOVED,e))}match(e){return e.hasAllComponents(this.Components)&&!e.hasAnyComponents(this.NotComponents)}toJSON(){return{key:this.key,reactive:this.reactive,components:{included:this.Components.map(e=>e.name),not:this.NotComponents.map(e=>e.name)},numEntities:this.entities.length}}stats(){return{numComponents:this.Components.length,numEntities:this.entities.length}}}Query.prototype.ENTITY_ADDED="Query#ENTITY_ADDED",Query.prototype.ENTITY_REMOVED="Query#ENTITY_REMOVED",Query.prototype.COMPONENT_CHANGED="Query#COMPONENT_CHANGED";class Component{constructor(e){if(!1!==e){const t=this.constructor.schema;for(const n in t)if(e&&e.hasOwnProperty(n))this[n]=e[n];else{const e=t[n];if(e.hasOwnProperty("default"))this[n]=e.type.clone(e.default);else{const t=e.type;this[n]=t.clone(t.default)}}}this._pool=null}copy(e){const t=this.constructor.schema;for(const n in t){const o=t[n];e.hasOwnProperty(n)&&(this[n]=o.type.copy(e[n],this[n]))}return this}clone(){return(new this.constructor).copy(this)}reset(){const e=this.constructor.schema;for(const t in e){const n=e[t];if(n.hasOwnProperty("default"))this[t]=n.type.copy(n.default,this[t]);else{const e=n.type;this[t]=e.copy(e.default,this[t])}}}dispose(){this._pool&&this._pool.release(this)}}Component.schema={},Component.isComponent=!0;class System{canExecute(){if(0===this._mandatoryQueries.length)return!0;for(let e=0;e<this._mandatoryQueries.length;e++){if(0===this._mandatoryQueries[e].entities.length)return!1}return!0}constructor(e,t){if(this.world=e,this.enabled=!0,this._queries={},this.queries={},this.priority=0,this.executeTime=0,t&&t.priority&&(this.priority=t.priority),this._mandatoryQueries=[],this.initialized=!0,this.constructor.queries)for(var n in this.constructor.queries){var o=this.constructor.queries[n],s=o.components;if(!s||0===s.length)throw new Error("'components' attribute can't be empty in a query");var r=this.world.entityManager.queryComponents(s);this._queries[n]=r,!0===o.mandatory&&this._mandatoryQueries.push(r),this.queries[n]={results:r.entities};var i=["added","removed","changed"];const e={added:Query.prototype.ENTITY_ADDED,removed:Query.prototype.ENTITY_REMOVED,changed:Query.prototype.COMPONENT_CHANGED};o.listen&&i.forEach(t=>{if(this.execute||console.warn(`System '${this.constructor.name}' has defined listen events (${i.join(", ")}) for query '${n}' but it does not implement the 'execute' method.`),o.listen[t]){let s=o.listen[t];if("changed"===t){if(r.reactive=!0,!0===s){let e=this.queries[n][t]=[];r.eventDispatcher.addEventListener(Query.prototype.COMPONENT_CHANGED,t=>{-1===e.indexOf(t)&&e.push(t)})}else if(Array.isArray(s)){let e=this.queries[n][t]=[];r.eventDispatcher.addEventListener(Query.prototype.COMPONENT_CHANGED,(t,n)=>{-1!==s.indexOf(n.constructor)&&-1===e.indexOf(t)&&e.push(t)})}}else{let o=this.queries[n][t]=[];r.eventDispatcher.addEventListener(e[t],e=>{-1===o.indexOf(e)&&o.push(e)})}}})}}stop(){this.executeTime=0,this.enabled=!1}play(){this.enabled=!0}clearEvents(){for(let t in this.queries){var e=this.queries[t];if(e.added&&(e.added.length=0),e.removed&&(e.removed.length=0),e.changed)if(Array.isArray(e.changed))e.changed.length=0;else for(let t in e.changed)e.changed[t].length=0}}toJSON(){var e={name:this.constructor.name,enabled:this.enabled,executeTime:this.executeTime,priority:this.priority,queries:{}};if(this.constructor.queries){var t=this.constructor.queries;for(let n in t){let o=this.queries[n],s=t[n],r=e.queries[n]={key:this._queries[n].key};if(r.mandatory=!0===s.mandatory,r.reactive=s.listen&&(!0===s.listen.added||!0===s.listen.removed||!0===s.listen.changed||Array.isArray(s.listen.changed)),r.reactive){r.listen={};["added","removed","changed"].forEach(e=>{o[e]&&(r.listen[e]={entities:o[e].length})})}}}return e}}System.isSystem=!0;class TagComponent extends Component{constructor(){super(!1)}}TagComponent.isTagComponent=!0;const copyValue=e=>e,cloneValue=e=>e,copyArray=(e,t)=>{const n=e,o=t;o.length=0;for(let e=0;e<n.length;e++)o.push(n[e]);return o},cloneArray=e=>e.slice(),copyJSON=e=>JSON.parse(JSON.stringify(e)),cloneJSON=e=>JSON.parse(JSON.stringify(e)),copyCopyable=(e,t)=>t.copy(e),cloneClonable=e=>e.clone();function createType(e){var t=["name","default","copy","clone"].filter(t=>!e.hasOwnProperty(t));if(t.length>0)throw new Error("createType expects a type definition with the following properties: "+t.join(", "));return e.isType=!0,e}const Types={Number:createType({name:"Number",default:0,copy:copyValue,clone:cloneValue}),Boolean:createType({name:"Boolean",default:!1,copy:copyValue,clone:cloneValue}),String:createType({name:"String",default:"",copy:copyValue,clone:cloneValue}),Array:createType({name:"Array",default:[],copy:copyArray,clone:cloneArray}),Ref:createType({name:"Ref",default:void 0,copy:copyValue,clone:cloneValue}),JSON:createType({name:"JSON",default:null,copy:copyJSON,clone:cloneJSON})};function generateId(e){for(var t="",n="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",o=n.length,s=0;s<e;s++)t+=n.charAt(Math.floor(Math.random()*o));return t}function injectScript(e,t){var n=document.createElement("script");n.src=e,n.onload=t,(document.head||document.documentElement).appendChild(n)}function hookConsoleAndErrors(e){["error","warning","log"].forEach(t=>{if("function"==typeof console[t]){var n=console[t].bind(console);console[t]=(...o)=>(e.send({method:"console",type:t,args:JSON.stringify(o)}),n.apply(null,o))}}),window.addEventListener("error",t=>{e.send({method:"error",error:JSON.stringify({message:t.error.message,stack:t.error.stack})})})}function includeRemoteIdHTML(e){let t=document.createElement("div");return t.style.cssText="\n    align-items: center;\n    background-color: #333;\n    color: #aaa;\n    display:flex;\n    font-family: Arial;\n    font-size: 1.1em;\n    height: 40px;\n    justify-content: center;\n    left: 0;\n    opacity: 0.9;\n    position: absolute;\n    right: 0;\n    text-align: center;\n    top: 0;\n  ",t.innerHTML=`Open ECSY devtools to connect to this page using the code:&nbsp;<b style="color: #fff">${e}</b>&nbsp;<button onClick="generateNewCode()">Generate new code</button>`,document.body.appendChild(t),t}function enableRemoteDevtools(remoteId){if(!hasWindow)return void console.warn("Remote devtools not available outside the browser");window.generateNewCode=()=>{window.localStorage.clear(),remoteId=generateId(6),window.localStorage.setItem("ecsyRemoteId",remoteId),window.location.reload(!1)},remoteId=remoteId||window.localStorage.getItem("ecsyRemoteId"),remoteId||(remoteId=generateId(6),window.localStorage.setItem("ecsyRemoteId",remoteId));let infoDiv=includeRemoteIdHTML(remoteId);window.__ECSY_REMOTE_DEVTOOLS_INJECTED=!0,window.__ECSY_REMOTE_DEVTOOLS={};let Version="",worldsBeforeLoading=[],onWorldCreated=e=>{var t=e.detail.world;Version=e.detail.version,worldsBeforeLoading.push(t)};window.addEventListener("ecsy-world-created",onWorldCreated);let onLoaded=()=>{var peer=new Peer(remoteId);peer.on("open",()=>{peer.on("connection",connection=>{window.__ECSY_REMOTE_DEVTOOLS.connection=connection,connection.on("open",(function(){infoDiv.innerHTML="Connected",connection.on("data",(function(data){if("init"===data.type){var script=document.createElement("script");script.setAttribute("type","text/javascript"),script.onload=()=>{script.parentNode.removeChild(script),window.removeEventListener("ecsy-world-created",onWorldCreated),worldsBeforeLoading.forEach(e=>{var t=new CustomEvent("ecsy-world-created",{detail:{world:e,version:Version}});window.dispatchEvent(t)})},script.innerHTML=data.script,(document.head||document.documentElement).appendChild(script),script.onload(),hookConsoleAndErrors(connection)}else if("executeScript"===data.type){let value=eval(data.script);data.returnEval&&connection.send({method:"evalReturn",value:value})}}))}))})})};injectScript("https://cdn.jsdelivr.net/npm/peerjs@0.3.20/dist/peer.min.js",onLoaded)}if(hasWindow){const e=new URLSearchParams(window.location.search);e.has("enable-remote-devtools")&&enableRemoteDevtools()}class MousePosition{constructor(){this.current={x:0,y:0},this.prev={x:0,y:0}}copy(e){return this.current=e.current,this.prev=e.prev,this}set(e,t){return this.current=e,this.prev=t,this}clone(){return(new MousePosition).set(this.current,this.prev)}}const MousePositionType=createType({name:"MousePosition",default:new MousePosition,copy:copyCopyable,clone:cloneClonable});var ActionState;!function(e){e[e.START=0]="START",e[e.END=1]="END"}(ActionState||(ActionState={}));var ActionState$1=ActionState;class TemporalButtonState{constructor(){this.current=ActionState$1.END,this.prev=ActionState$1.END,this.changed=!1}set(e,t,n){return e&&(this.current=e),t&&(this.prev=t),n&&(this.changed=n),this}copy(e){var t;this.current=null!==(t=e.current)&&void 0!==t?t:ActionState$1.END,this.prev=ActionState$1.END,this.changed=!1}clone(){return new TemporalButtonState}}const TemporalButtonStateType=createType({name:"TemporalButtonState",default:new TemporalButtonState,copy:copyCopyable,clone:cloneClonable});class MouseInput extends Component{}MouseInput.schema={mouseButtonLeft:{type:TemporalButtonStateType},mouseButtonMiddle:{type:TemporalButtonStateType},mouseButtonRight:{type:TemporalButtonStateType},mousePosition:{type:MousePositionType},lastMovementTimestamp:{type:Types.Number},downHandler:{type:Types.Ref},moveHandler:{type:Types.Ref},upHandler:{type:Types.Ref}};const MouseButtonMappings={LEFT:{name:"leftMouseButton",value:0},RIGHT:{name:"rightMouseButton",value:2},MIDDLE:{name:"middleMouseButton",value:1}};class MouseInputSystem extends System{constructor(){super(...arguments),this.moveHandler=(e,t)=>{const{clientX:n,clientY:o,timeStamp:s}=e;t.mousePosition={x:n,y:o},t.lastTimestamp=s},this.buttonHandler=(e,t,n)=>{e.button===MouseButtonMappings.LEFT.value?n!==t.mouseButtonLeft.current?(t.mouseButtonLeft.prev=t.mouseButtonLeft.current,t.mouseButtonLeft.current=n,t.mouseButtonLeft.changed=!0):t.mouseButtonLeft.changed=!1:e.button===MouseButtonMappings.RIGHT.value?n!==t.mouseButtonRight.current?(t.mouseButtonRight.prev=t.mouseButtonRight.current,t.mouseButtonRight.current=n,t.mouseButtonRight.changed=!0):t.mouseButtonRight.changed=!1:n!==t.mouseButtonMiddle.current?(t.mouseButtonMiddle.prev=t.mouseButtonLeft.current,t.mouseButtonMiddle.current=n,t.mouseButtonMiddle.changed=!0):t.mouseButtonMiddle.changed=!1}}execute(){this.queries.mouse.added.forEach(e=>{this.mouse=e.getMutableComponent(MouseInput),document.addEventListener("mousemove",e=>this.moveHandler(e,this.mouse),!1),document.addEventListener("mousedown",e=>this.buttonHandler(e,this.mouse,ActionState$1.START),!1),document.addEventListener("mouseup",e=>this.buttonHandler(e,this.mouse,ActionState$1.END),!1)}),this.queries.mouse.removed.forEach(e=>{const t=e.getComponent(MouseInput);t&&document.removeEventListener("mousemove",t.upHandler),t&&document.removeEventListener("mousedown",t.downHandler),t&&document.removeEventListener("mouseup",t.moveHandler)})}}var Actions;MouseInputSystem.queries={mouse:{components:[MouseInput],listen:{added:!0,removed:!0}}},function(e){e[e.FORWARD=0]="FORWARD",e[e.BACKWARD=1]="BACKWARD",e[e.UP=2]="UP",e[e.DOWN=3]="DOWN",e[e.LEFT=4]="LEFT",e[e.RIGHT=5]="RIGHT",e[e.INTERACT=6]="INTERACT",e[e.CROUCH=7]="CROUCH",e[e.JUMP=8]="JUMP",e[e.WALK=9]="WALK",e[e.RUN=10]="RUN",e[e.SPRINT=11]="SPRINT"}(Actions||(Actions={}));var Actions$1=Actions;const KeyboardInputActionMap={w:Actions$1.FORWARD,a:Actions$1.LEFT,s:Actions$1.RIGHT,d:Actions$1.BACKWARD};class KeyboardInput extends Component{constructor(){super(...arguments),this.keyboardInputActionMap=KeyboardInputActionMap}}KeyboardInput.schema={keys:{type:Types.Ref,default:KeyboardInputActionMap}};class ActionBuffer{constructor(e){if(this.buffer=[],this.pos=0,e<0)throw new RangeError("The size does not allow negative values.");this.size=e}static fromArray(e,t=0){const n=new ActionBuffer(t);return n.fromArray(e,0===t),n}copy(){const e=new ActionBuffer(this.getBufferLength());return e.buffer=this.buffer,e}clone(){const e=new ActionBuffer(this.getBufferLength());return e.buffer=this.buffer,e}getSize(){return this.size}getPos(){return this.pos}getBufferLength(){return this.buffer.length}add(...e){e.forEach(e=>{this.buffer[this.pos]=e,this.pos=(this.pos+1)%this.size})}get(e){if(e<0&&(e+=this.buffer.length),!(e<0||e>this.buffer.length))return this.buffer.length<this.size?this.buffer[e]:this.buffer[(this.pos+e)%this.size]}getFirst(){return this.get(0)}getLast(){return this.get(-1)}remove(e,t=1){if(e<0&&(e+=this.buffer.length),e<0||e>this.buffer.length)return[];const n=this.toArray(),o=n.splice(e,t);return this.fromArray(n),o}pop(){return this.remove(0)[0]}popLast(){return this.remove(-1)[0]}toArray(){return this.buffer.slice(this.pos).concat(this.buffer.slice(0,this.pos))}fromArray(e,t=!1){if(!Array.isArray(e))throw new TypeError("Input value is not an array.");t&&this.resize(e.length),0!==this.size&&(this.buffer=e.slice(-this.size),this.pos=this.buffer.length%this.size)}clear(){this.buffer=[],this.pos=0}resize(e){if(e<0)throw new RangeError("The size does not allow negative values.");if(0===e)this.clear();else if(e!==this.size){const t=this.toArray();this.fromArray(t.slice(-e)),this.pos=this.buffer.length%e}this.size=e}full(){return this.buffer.length===this.size}empty(){return 0===this.buffer.length}}const ActionBufferType=createType({name:"ActionBuffer",default:new ActionBuffer(5),copy:copyCopyable,clone:cloneClonable});class ActionQueue extends Component{}ActionQueue.schema={actions:{type:ActionBufferType,default:new ActionBuffer(10)}};class KeyboardInputSystem extends System{execute(){this.queries.keyboard.added.forEach(e=>{document.addEventListener("keydown",t=>{this.mapKeyToAction(e,t.key,ActionState$1.START)}),document.addEventListener("keyup",t=>{this.mapKeyToAction(e,t.key,ActionState$1.END)})}),this.queries.keyboard.removed.forEach(e=>{document.removeEventListener("keydown",t=>{this.mapKeyToAction(e,t.key,ActionState$1.START)}),document.removeEventListener("keyup",t=>{this.mapKeyToAction(e,t.key,ActionState$1.END)})})}mapKeyToAction(e,t,n){this.kb=e.getComponent(KeyboardInput),void 0!==this.kb.keyboardInputActionMap[t]&&e.getComponent(ActionQueue).actions.add({action:this.kb.keyboardInputActionMap[t],state:n})}}KeyboardInputSystem.queries={keyboard:{components:[KeyboardInput,ActionQueue],listen:{added:!0,removed:!0}}};class GamepadInput extends Component{}GamepadInput.schema={axis_threshold:{type:Types.Number,default:.1},connected:{type:Types.Boolean,default:!1},dpadOneAxisY:{type:Types.Number},dpadOneAxisX:{type:Types.Number},dpadTwoAxisY:{type:Types.Number},dpadTwoAxisX:{type:Types.Number},buttonA:{type:Types.Boolean},buttonB:{type:Types.Boolean},buttonX:{type:Types.Boolean},buttonY:{type:Types.Boolean}};class GamepadInputSystem extends System{execute(){this.queries.gamepad.added.forEach(e=>{const t=e.getMutableComponent(GamepadInput);window.addEventListener("gamepadconnected",e=>{console.log("A gamepad connected:",e.gamepad),t.connected=!0}),window.addEventListener("gamepaddisconnected",e=>{console.log("A gamepad disconnected:",e.gamepad),t.connected=!1})}),this.queries.gamepad.results.forEach(e=>{const t=e.getMutableComponent(GamepadInput);if(t.connected){const e=navigator.getGamepads();for(let n=0;n<e.length;n++)e[n].axes&&e[n].axes.length>=2&&((e[n].axes[0]<-t.axis_threshold||e[n].axes[0]>t.axis_threshold)&&(0==n?t.dpadOneAxisX=e[n].axes[0]:1==n&&(t.dpadTwoAxisX=e[n].axes[0])),(e[n].axes[1]<-t.axis_threshold||e[n].axes[1]>t.axis_threshold)&&(0==n?t.dpadOneAxisY=e[n].axes[1]:1==n&&(t.dpadTwoAxisY=e[n].axes[1])))}})}}GamepadInputSystem.queries={gamepad:{components:[GamepadInput],listen:{added:!0,removed:!0}}};const isBrowser="undefined"!=typeof window&&void 0!==window.document;class Input extends TagComponent{}class KeyboardDebugSystem extends System{execute(){this.queries.keyboard.changed.forEach(e=>{const t=e.getComponent(KeyboardInput);console.log(t.keyboardInputActionMap);const n=e.getComponent(ActionQueue);console.log(n.actions.toArray())})}}KeyboardDebugSystem.queries={keyboard:{components:[KeyboardInput,ActionQueue],listen:{changed:!0}}};const DEFAULT_OPTIONS={mouse:!0,keyboard:!0,touchscreen:!0,gamepad:!0,debug:!1};function initializeInputSystems(e,t=DEFAULT_OPTIONS,n,o,s,r){if(t.debug&&console.log("Initializing input systems..."),!isBrowser)return console.error("Couldn't initialize input, are you in a browser?");window&&t.debug&&(window.DEBUG_INPUT=!0),t.debug&&(console.log("Registering input systems with the following options:"),console.log(t));const i=e.createEntity();e.registerComponent(Input),e.registerComponent(ActionQueue),i.addComponent(Input),i.addComponent(ActionQueue),t.keyboard&&(e.registerComponent(KeyboardInput).registerSystem(KeyboardInputSystem,null),i.addComponent(KeyboardInput),t.debug&&e.registerSystem(KeyboardDebugSystem),console.log("Registered KeyboardInputSystem and added KeyboardInput component to input entity")),t.mouse&&(e.registerComponent(MouseInput).registerSystem(MouseInputSystem,null),i.addComponent(MouseInput),t.debug&&console.log("Registered MouseInputSystem and added MouseInput component to input entity")),t.gamepad&&(e.registerComponent(GamepadInput).registerSystem(GamepadInputSystem,null),i.addComponent(GamepadInput),t.debug&&console.log("Registered GamepadInputSystem and added MouseInput component to input entity")),t.touchscreen&&t.debug&&console.log("Touchscreen is not yet implemented"),t.debug&&console.log("INPUT: Registered input systems.")}export{initializeInputSystems};
