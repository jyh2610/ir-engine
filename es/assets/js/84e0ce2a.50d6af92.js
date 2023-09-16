"use strict";(self.webpackChunk_etherealengine_docs=self.webpackChunk_etherealengine_docs||[]).push([[6729],{3905:(e,t,r)=>{r.d(t,{Zo:()=>u,kt:()=>f});var n=r(7294);function o(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){o(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,o=function(e,t){if(null==e)return{};var r,n,o={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(o[r]=e[r]);return o}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(o[r]=e[r])}return o}var l=n.createContext({}),p=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},u=function(e){var t=p(e.components);return n.createElement(l.Provider,{value:t},e.children)},c="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,o=e.mdxType,a=e.originalType,l=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),c=p(r),m=o,f=c["".concat(l,".").concat(m)]||c[m]||d[m]||a;return r?n.createElement(f,i(i({ref:t},u),{},{components:r})):n.createElement(f,i({ref:t},u))}));function f(e,t){var r=arguments,o=t&&t.mdxType;if("string"==typeof e||o){var a=r.length,i=new Array(a);i[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[c]="string"==typeof e?e:o,i[1]=s;for(var p=2;p<a;p++)i[p]=r[p];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},3198:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>i,default:()=>d,frontMatter:()=>a,metadata:()=>s,toc:()=>p});var n=r(7462),o=(r(7294),r(3905));const a={},i="Database Migrations",s={unversionedId:"host/devops_deployment/feathers_sequelize",id:"host/devops_deployment/feathers_sequelize",title:"Database Migrations",description:"Migrations",source:"@site/docs/1_host/2_devops_deployment/3_feathers_sequelize.md",sourceDirName:"1_host/2_devops_deployment",slug:"/host/devops_deployment/feathers_sequelize",permalink:"/etherealengine-docs/es/docs/host/devops_deployment/feathers_sequelize",draft:!1,editUrl:"https://github.com/EtherealEngine/etherealengine-docs/blob/master/docs/1_host/2_devops_deployment/3_feathers_sequelize.md",tags:[],version:"current",sidebarPosition:3,frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"Installing Projects",permalink:"/etherealengine-docs/es/docs/host/devops_deployment/installing_projects"},next:{title:"How to set up GitHub to install external projects",permalink:"/etherealengine-docs/es/docs/host/devops_deployment/setup_github_oauth_for_projects"}},l={},p=[{value:"Migrations",id:"migrations",level:2},{value:"Generate Migration file",id:"generate-migration-file",level:3},{value:"Migrate the database",id:"migrate-the-database",level:3},{value:"For more information",id:"for-more-information",level:3},{value:"OpenAPI",id:"openapi",level:2}],u={toc:p},c="wrapper";function d(e){let{components:t,...r}=e;return(0,o.kt)(c,(0,n.Z)({},u,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("h1",{id:"database-migrations"},"Database Migrations"),(0,o.kt)("h2",{id:"migrations"},"Migrations"),(0,o.kt)("h3",{id:"generate-migration-file"},"Generate Migration file"),(0,o.kt)("p",null,(0,o.kt)("inlineCode",{parentName:"p"},'node_modules/.bin/sequelize migration:generate --name "migration_name"')),(0,o.kt)("h3",{id:"migrate-the-database"},"Migrate the database"),(0,o.kt)("p",null,"Before run the server, you should migrate the db.\nTo do this, please run as following.\n",(0,o.kt)("inlineCode",{parentName:"p"},"npm run compile"),"\n",(0,o.kt)("inlineCode",{parentName:"p"},"node_modules/.bin/sequelize db:migrate")),(0,o.kt)("h3",{id:"for-more-information"},"For more information"),(0,o.kt)("p",null,"For more information, please visit here\n",(0,o.kt)("a",{parentName:"p",href:"https://github.com/douglas-treadwell/sequelize-cli-typescript"},"https://github.com/douglas-treadwell/sequelize-cli-typescript")),(0,o.kt)("h2",{id:"openapi"},"OpenAPI"),(0,o.kt)("p",null,"Our server is set up with Swagger documentation to automatically generate from most endpoints. A few custom routes are not documented at this time, but most of the basic stuff is."),(0,o.kt)("p",null,"You can see the docs for a running Ethereal Engine instance locally at:"),(0,o.kt)("pre",null,(0,o.kt)("code",{parentName:"pre"},"https://localhost:3030/openapi\n")),(0,o.kt)("p",null,"Or on our ",(0,o.kt)("a",{parentName:"p",href:"https://api-dev.etherealengine.com/openapi"},"dev cluster")))}d.isMDXComponent=!0}}]);