"use strict";(self.webpackChunk_etherealengine_docs=self.webpackChunk_etherealengine_docs||[]).push([[3976],{3905:(e,t,a)=>{a.d(t,{Zo:()=>c,kt:()=>m});var r=a(7294);function i(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function l(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,r)}return a}function d(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?l(Object(a),!0).forEach((function(t){i(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):l(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function n(e,t){if(null==e)return{};var a,r,i=function(e,t){if(null==e)return{};var a,r,i={},l=Object.keys(e);for(r=0;r<l.length;r++)a=l[r],t.indexOf(a)>=0||(i[a]=e[a]);return i}(e,t);if(Object.getOwnPropertySymbols){var l=Object.getOwnPropertySymbols(e);for(r=0;r<l.length;r++)a=l[r],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(i[a]=e[a])}return i}var o=r.createContext({}),s=function(e){var t=r.useContext(o),a=t;return e&&(a="function"==typeof e?e(t):d(d({},t),e)),a},c=function(e){var t=s(e.components);return r.createElement(o.Provider,{value:t},e.children)},v="mdxType",u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},h=r.forwardRef((function(e,t){var a=e.components,i=e.mdxType,l=e.originalType,o=e.parentName,c=n(e,["components","mdxType","originalType","parentName"]),v=s(a),h=i,m=v["".concat(o,".").concat(h)]||v[h]||u[h]||l;return a?r.createElement(m,d(d({ref:t},c),{},{components:a})):r.createElement(m,d({ref:t},c))}));function m(e,t){var a=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var l=a.length,d=new Array(l);d[0]=h;var n={};for(var o in t)hasOwnProperty.call(t,o)&&(n[o]=t[o]);n.originalType=e,n[v]="string"==typeof e?e:i,d[1]=n;for(var s=2;s<l;s++)d[s]=a[s];return r.createElement.apply(null,d)}return r.createElement.apply(null,a)}h.displayName="MDXCreateElement"},1868:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>o,contentTitle:()=>d,default:()=>u,frontMatter:()=>l,metadata:()=>n,toc:()=>s});var r=a(7462),i=(a(7294),a(3905));const l={},d="Ethereal Engine Admin Panel Guide",n={unversionedId:"host/Admin_Dashboard/readme",id:"host/Admin_Dashboard/readme",title:"Ethereal Engine Admin Panel Guide",description:"Dashboard",source:"@site/docs/1_host/3_Admin_Dashboard/readme.md",sourceDirName:"1_host/3_Admin_Dashboard",slug:"/host/Admin_Dashboard/",permalink:"/etherealengine-docs/docs/host/Admin_Dashboard/",draft:!1,editUrl:"https://github.com/EtherealEngine/etherealengine-docs/blob/master/docs/1_host/3_Admin_Dashboard/readme.md",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"Getting Started",permalink:"/etherealengine-docs/docs/host/devops_deployment/tutorials/ethereal_control_center/getting_started"},next:{title:"Ethereal for Creators",permalink:"/etherealengine-docs/docs/creator/"}},o={},s=[{value:"Dashboard",id:"dashboard",level:2},{value:"Usage Dashboard",id:"usage-dashboard",level:3},{value:"Usage Time Series",id:"usage-time-series",level:3},{value:"Projects",id:"projects",level:2},{value:"Managing Projects",id:"managing-projects",level:3},{value:"Project Table",id:"project-table",level:3},{value:"Name",id:"name",level:4},{value:"Version",id:"version",level:4},{value:"Commit SHA",id:"commit-sha",level:4},{value:"Commit Date",id:"commit-date",level:4},{value:"Update",id:"update",level:4},{value:"GitHub Integration",id:"github-integration",level:4},{value:"User Access",id:"user-access",level:4},{value:"Invalidate Cache",id:"invalidate-cache",level:4},{value:"View Project Files",id:"view-project-files",level:4},{value:"Routes",id:"routes",level:2},{value:"Location",id:"location",level:2},{value:"Create Location",id:"create-location",level:3},{value:"Name",id:"name-1",level:4},{value:"Max Users",id:"max-users",level:4},{value:"Scene",id:"scene",level:4},{value:"Type",id:"type",level:4},{value:"Media Toggles",id:"media-toggles",level:4},{value:"Make Lobby",id:"make-lobby",level:4},{value:"Featured",id:"featured",level:4},{value:"Location Table",id:"location-table",level:3},{value:"Instance",id:"instance",level:2},{value:"Patch InstanceServer",id:"patch-instanceserver",level:3},{value:"Instance Table",id:"instance-table",level:3},{value:"Instance Table Actions",id:"instance-table-actions",level:3},{value:"Users",id:"users",level:2},{value:"Create User",id:"create-user",level:3},{value:"Name",id:"name-2",level:4},{value:"Avatar",id:"avatar",level:4},{value:"Scopes",id:"scopes",level:4},{value:"Admin:Admin",id:"adminadmin",level:5},{value:"Benchmarking:read/write",id:"benchmarkingreadwrite",level:5},{value:"Bot:read/write",id:"botreadwrite",level:5},{value:"contentPacks:read/write",id:"contentpacksreadwrite",level:5},{value:"Editor:write",id:"editorwrite",level:5},{value:"globalAvatars:read/write",id:"globalavatarsreadwrite",level:5},{value:"Groups:read/write",id:"groupsreadwrite",level:5},{value:"Instance:read/write",id:"instancereadwrite",level:5},{value:"Invite:read",id:"inviteread",level:5},{value:"Location:read/write",id:"locationreadwrite",level:5},{value:"Party:read/write",id:"partyreadwrite",level:5},{value:"Projects:read/write",id:"projectsreadwrite",level:5},{value:"realityPacks:read/write",id:"realitypacksreadwrite",level:5},{value:"Recording:read/write",id:"recordingreadwrite",level:5},{value:"Routes:read/write",id:"routesreadwrite",level:5},{value:"Scene:read/write",id:"scenereadwrite",level:5},{value:"Server:read/write",id:"serverreadwrite",level:5},{value:"Settings:read/write",id:"settingsreadwrite",level:5},{value:"Static_resource:read/write",id:"static_resourcereadwrite",level:5},{value:"User:read/write",id:"userreadwrite",level:5},{value:"User Table",id:"user-table",level:3},{value:"Invites",id:"invites",level:2},{value:"Avatar",id:"avatar-1",level:2},{value:"Create Avatar",id:"create-avatar",level:3},{value:"Avatar Name",id:"avatar-name",level:4},{value:"File Source",id:"file-source",level:4},{value:"Avatar Thumbnail",id:"avatar-thumbnail",level:4},{value:"Avatar Table",id:"avatar-table",level:3},{value:"Resources",id:"resources",level:2},{value:"Create Resource",id:"create-resource",level:3},{value:"Name",id:"name-3",level:4},{value:"Project",id:"project",level:4},{value:"File Source",id:"file-source-1",level:4},{value:"Benchmarking",id:"benchmarking",level:2},{value:"Bots",id:"bots",level:2}],c={toc:s},v="wrapper";function u(e){let{components:t,...a}=e;return(0,i.kt)(v,(0,r.Z)({},c,a,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"ethereal-engine-admin-panel-guide"},"Ethereal Engine Admin Panel Guide"),(0,i.kt)("h2",{id:"dashboard"},"Dashboard"),(0,i.kt)("h3",{id:"usage-dashboard"},"Usage Dashboard"),(0,i.kt)("h3",{id:"usage-time-series"},"Usage Time Series"),(0,i.kt)("h2",{id:"projects"},"Projects"),(0,i.kt)("h3",{id:"managing-projects"},"Managing Projects"),(0,i.kt)("h3",{id:"project-table"},"Project Table"),(0,i.kt)("h4",{id:"name"},"Name"),(0,i.kt)("h4",{id:"version"},"Version"),(0,i.kt)("h4",{id:"commit-sha"},"Commit SHA"),(0,i.kt)("h4",{id:"commit-date"},"Commit Date"),(0,i.kt)("h4",{id:"update"},"Update"),(0,i.kt)("h4",{id:"github-integration"},"GitHub Integration"),(0,i.kt)("h4",{id:"user-access"},"User Access"),(0,i.kt)("h4",{id:"invalidate-cache"},"Invalidate Cache"),(0,i.kt)("h4",{id:"view-project-files"},"View Project Files"),(0,i.kt)("h2",{id:"routes"},"Routes"),(0,i.kt)("h2",{id:"location"},"Location"),(0,i.kt)("h3",{id:"create-location"},"Create Location"),(0,i.kt)("h4",{id:"name-1"},"Name"),(0,i.kt)("h4",{id:"max-users"},"Max Users"),(0,i.kt)("h4",{id:"scene"},"Scene"),(0,i.kt)("h4",{id:"type"},"Type"),(0,i.kt)("h4",{id:"media-toggles"},"Media Toggles"),(0,i.kt)("h4",{id:"make-lobby"},"Make Lobby"),(0,i.kt)("h4",{id:"featured"},"Featured"),(0,i.kt)("h3",{id:"location-table"},"Location Table"),(0,i.kt)("h2",{id:"instance"},"Instance"),(0,i.kt)("h3",{id:"patch-instanceserver"},"Patch InstanceServer"),(0,i.kt)("h3",{id:"instance-table"},"Instance Table"),(0,i.kt)("h3",{id:"instance-table-actions"},"Instance Table Actions"),(0,i.kt)("h2",{id:"users"},"Users"),(0,i.kt)("h3",{id:"create-user"},"Create User"),(0,i.kt)("h4",{id:"name-2"},"Name"),(0,i.kt)("h4",{id:"avatar"},"Avatar"),(0,i.kt)("h4",{id:"scopes"},"Scopes"),(0,i.kt)("h5",{id:"adminadmin"},"Admin:Admin"),(0,i.kt)("h5",{id:"benchmarkingreadwrite"},"Benchmarking:read/write"),(0,i.kt)("h5",{id:"botreadwrite"},"Bot:read/write"),(0,i.kt)("h5",{id:"contentpacksreadwrite"},"contentPacks:read/write"),(0,i.kt)("h5",{id:"editorwrite"},"Editor:write"),(0,i.kt)("h5",{id:"globalavatarsreadwrite"},"globalAvatars:read/write"),(0,i.kt)("h5",{id:"groupsreadwrite"},"Groups:read/write"),(0,i.kt)("h5",{id:"instancereadwrite"},"Instance:read/write"),(0,i.kt)("h5",{id:"inviteread"},"Invite:read"),(0,i.kt)("h5",{id:"locationreadwrite"},"Location:read/write"),(0,i.kt)("h5",{id:"partyreadwrite"},"Party:read/write"),(0,i.kt)("h5",{id:"projectsreadwrite"},"Projects:read/write"),(0,i.kt)("h5",{id:"realitypacksreadwrite"},"realityPacks:read/write"),(0,i.kt)("h5",{id:"recordingreadwrite"},"Recording:read/write"),(0,i.kt)("h5",{id:"routesreadwrite"},"Routes:read/write"),(0,i.kt)("h5",{id:"scenereadwrite"},"Scene:read/write"),(0,i.kt)("h5",{id:"serverreadwrite"},"Server:read/write"),(0,i.kt)("h5",{id:"settingsreadwrite"},"Settings:read/write"),(0,i.kt)("h5",{id:"static_resourcereadwrite"},"Static_resource:read/write"),(0,i.kt)("h5",{id:"userreadwrite"},"User:read/write"),(0,i.kt)("h3",{id:"user-table"},"User Table"),(0,i.kt)("h2",{id:"invites"},"Invites"),(0,i.kt)("h2",{id:"avatar-1"},"Avatar"),(0,i.kt)("h3",{id:"create-avatar"},"Create Avatar"),(0,i.kt)("h4",{id:"avatar-name"},"Avatar Name"),(0,i.kt)("h4",{id:"file-source"},"File Source"),(0,i.kt)("h4",{id:"avatar-thumbnail"},"Avatar Thumbnail"),(0,i.kt)("h3",{id:"avatar-table"},"Avatar Table"),(0,i.kt)("h2",{id:"resources"},"Resources"),(0,i.kt)("h3",{id:"create-resource"},"Create Resource"),(0,i.kt)("h4",{id:"name-3"},"Name"),(0,i.kt)("h4",{id:"project"},"Project"),(0,i.kt)("h4",{id:"file-source-1"},"File Source"),(0,i.kt)("h2",{id:"benchmarking"},"Benchmarking"),(0,i.kt)("p",null,"In work"),(0,i.kt)("h2",{id:"bots"},"Bots"),(0,i.kt)("p",null,"In work"))}u.isMDXComponent=!0}}]);