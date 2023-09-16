"use strict";(self.webpackChunk_etherealengine_docs=self.webpackChunk_etherealengine_docs||[]).push([[8953],{3905:(e,t,r)=>{r.d(t,{Zo:()=>p,kt:()=>y});var n=r(7294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var c=n.createContext({}),l=function(e){var t=n.useContext(c),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},p=function(e){var t=l(e.components);return n.createElement(c.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,a=e.originalType,c=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),u=l(r),m=o,y=u["".concat(c,".").concat(m)]||u[m]||d[m]||a;return r?n.createElement(y,i(i({ref:t},p),{},{components:r})):n.createElement(y,i({ref:t},p))}));function y(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var a=r.length,i=new Array(a);i[0]=m;var s={};for(var c in t)hasOwnProperty.call(t,c)&&(s[c]=t[c]);s.originalType=e,s[u]="string"==typeof e?e:o,i[1]=s;for(var l=2;l<a;l++)i[l]=r[l];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},8359:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>c,contentTitle:()=>i,default:()=>d,frontMatter:()=>a,metadata:()=>s,toc:()=>l});var n=r(7462),o=(r(7294),r(3905));const a={},i="Networking",s={unversionedId:"creator/development/networking",id:"creator/development/networking",title:"Networking",description:"Networks",source:"@site/docs/2_creator/4_development/3_networking.md",sourceDirName:"2_creator/4_development",slug:"/creator/development/networking",permalink:"/etherealengine-docs/docs/creator/development/networking",draft:!1,editUrl:"https://github.com/EtherealEngine/etherealengine-docs/blob/master/docs/2_creator/4_development/3_networking.md",tags:[],version:"current",sidebarPosition:3,frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"Entities, Components and Systems",permalink:"/etherealengine-docs/docs/creator/development/ecs"},next:{title:"Event Sourcing",permalink:"/etherealengine-docs/docs/creator/development/actions_event_sourcing"}},c={},l=[{value:"Networks",id:"networks",level:2},{value:"Users &amp; Peers",id:"users--peers",level:2},{value:"Ownership and Authority",id:"ownership-and-authority",level:2}],p={toc:l},u="wrapper";function d(e){let{components:t,...r}=e;return(0,o.kt)(u,(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h1",{id:"networking"},"Networking"),(0,o.kt)("h2",{id:"networks"},"Networks"),(0,o.kt)("p",null,"Networks are a way of sharing topic specific data between certain peers. There are two types of networks, ",(0,o.kt)("strong",{parentName:"p"},"world")," and ",(0,o.kt)("strong",{parentName:"p"},"media")," networks, and are tied to location instances and media instances respectively."),(0,o.kt)("h2",{id:"users--peers"},"Users & Peers"),(0,o.kt)("p",null,"Users are unique accounts created in a particular Ethereal Engine deployment. Users can connect to multiple instances, and have multiple peers connected to each instance."),(0,o.kt)("h2",{id:"ownership-and-authority"},"Ownership and Authority"),(0,o.kt)("p",null,"Ownership specifies that a networked entity belongs to a particular user. Ownership cannot be transferred for an entity, the entity must be destroyed and recreated by a new user. "),(0,o.kt)("p",null,"Authority specifies that a networked entity can be controlled by a particular peer. Authority can be transferred between peers, and is done so by sending an authority request action to the owner peer, upon which the owner peer will send an authority transfer action to the requesting peer."))}d.isMDXComponent=!0}}]);