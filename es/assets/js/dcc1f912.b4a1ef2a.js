"use strict";(self.webpackChunk_etherealengine_docs=self.webpackChunk_etherealengine_docs||[]).push([[3666],{3905:(e,t,n)=>{n.d(t,{Zo:()=>d,kt:()=>h});var a=n(7294);function l(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function r(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);t&&(a=a.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,a)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?r(Object(n),!0).forEach((function(t){l(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):r(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,a,l=function(e,t){if(null==e)return{};var n,a,l={},r=Object.keys(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||(l[n]=e[n]);return l}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(a=0;a<r.length;a++)n=r[a],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(l[n]=e[n])}return l}var p=a.createContext({}),s=function(e){var t=a.useContext(p),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},d=function(e){var t=s(e.components);return a.createElement(p.Provider,{value:t},e.children)},u="mdxType",m={inlineCode:"code",wrapper:function(e){var t=e.children;return a.createElement(a.Fragment,{},t)}},c=a.forwardRef((function(e,t){var n=e.components,l=e.mdxType,r=e.originalType,p=e.parentName,d=o(e,["components","mdxType","originalType","parentName"]),u=s(n),c=l,h=u["".concat(p,".").concat(c)]||u[c]||m[c]||r;return n?a.createElement(h,i(i({ref:t},d),{},{components:n})):a.createElement(h,i({ref:t},d))}));function h(e,t){var n=arguments,l=t&&t.mdxType;if("string"==typeof e||l){var r=n.length,i=new Array(r);i[0]=c;var o={};for(var p in t)hasOwnProperty.call(t,p)&&(o[p]=t[p]);o.originalType=e,o[u]="string"==typeof e?e:l,i[1]=o;for(var s=2;s<r;s++)i[s]=n[s];return a.createElement.apply(null,i)}return a.createElement.apply(null,n)}c.displayName="MDXCreateElement"},1100:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>p,contentTitle:()=>i,default:()=>m,frontMatter:()=>r,metadata:()=>o,toc:()=>s});var a=n(7462),l=(n(7294),n(3905));const r={},i="Upgrading Helm Release",o={unversionedId:"host/devops_deployment/upgrade_helm_deployment",id:"host/devops_deployment/upgrade_helm_deployment",title:"Upgrading Helm Release",description:"This guide will cover various sections regarding upgrading an existing helm deployment.",source:"@site/docs/1_host/2_devops_deployment/7_upgrade_helm_deployment.md",sourceDirName:"1_host/2_devops_deployment",slug:"/host/devops_deployment/upgrade_helm_deployment",permalink:"/etherealengine-docs/es/docs/host/devops_deployment/upgrade_helm_deployment",draft:!1,editUrl:"https://github.com/EtherealEngine/etherealengine-docs/blob/master/docs/1_host/2_devops_deployment/7_upgrade_helm_deployment.md",tags:[],version:"current",sidebarPosition:7,frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"Release Helm Chart",permalink:"/etherealengine-docs/es/docs/host/devops_deployment/release_helm_chart"},next:{title:"Tutorials",permalink:"/etherealengine-docs/es/docs/host/devops_deployment/tutorials/"}},p={},s=[{value:"Getting Updated <code>values.yaml</code> File",id:"getting-updated-valuesyaml-file",level:2},{value:"Evaluating Difference in <code>value.yaml</code> &amp; Deployed Charts",id:"evaluating-difference-in-valueyaml--deployed-charts",level:2},{value:"Upgrading Helm Deployment",id:"upgrading-helm-deployment",level:2}],d={toc:s},u="wrapper";function m(e){let{components:t,...n}=e;return(0,l.kt)(u,(0,a.Z)({},d,n,{components:t,mdxType:"MDXLayout"}),(0,l.kt)("h1",{id:"upgrading-helm-release"},"Upgrading Helm Release"),(0,l.kt)("p",null,"This guide will cover various sections regarding upgrading an existing helm deployment."),(0,l.kt)("h2",{id:"getting-updated-valuesyaml-file"},"Getting Updated ",(0,l.kt)("inlineCode",{parentName:"h2"},"values.yaml")," File"),(0,l.kt)("p",null,"Usually a helm release upgrade is required when changes are made in configuration of helm charts. To do so first thing required is ",(0,l.kt)("inlineCode",{parentName:"p"},"value.yaml")," file of current configuration. If you already have an updated copy of this file then you can update the desired values and push the changes to helm deployment."),(0,l.kt)("p",null,"But for scenarios where multiple people are working same deployment, it becomes difficult to maintain updated ",(0,l.kt)("inlineCode",{parentName:"p"},"values.yaml")," file. At anytime you can get the current version/snapshot of ",(0,l.kt)("inlineCode",{parentName:"p"},"values.yaml")," file by running ",(0,l.kt)("a",{parentName:"p",href:"https://helm.sh/docs/helm/helm_get_values/"},"get values")," command:"),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre",className:"language-bash"},"helm get values [DEPLOYMENT_NAME]\n")),(0,l.kt)("p",null,"i.e."),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre",className:"language-bash"},"helm get values dev\n")),(0,l.kt)("p",null,"You can save the output in a ",(0,l.kt)("inlineCode",{parentName:"p"},"values.yaml")," file and update the required values."),(0,l.kt)("h2",{id:"evaluating-difference-in-valueyaml--deployed-charts"},"Evaluating Difference in ",(0,l.kt)("inlineCode",{parentName:"h2"},"value.yaml")," & Deployed Charts"),(0,l.kt)("p",null,"It become very handy if you can evaluate the differences between your local ",(0,l.kt)("inlineCode",{parentName:"p"},"values.yaml")," file and current deployment. This way you can beforehand visualize the changes a helm upgrade is going to make. To do so first make sure you have ",(0,l.kt)("inlineCode",{parentName:"p"},"helm diff")," plugin installed. You can install it by running:"),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre",className:"language-bash"},"helm plugin install https://github.com/databus23/helm-diff\n")),(0,l.kt)("p",null,"Once ",(0,l.kt)("inlineCode",{parentName:"p"},"helm diff")," plugin is installed then you can run following command:"),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre",className:"language-bash"},"helm diff upgrade [DEPLOYMENT_NAME] etherealengine/etherealengine --values [PATH_TO_VALUES_YAML]\n")),(0,l.kt)("p",null,"i.e."),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre",className:"language-bash"},"helm diff upgrade dev etherealengine/etherealengine --values ~/etherealengine-ops/values/dev.ethereal.values.yaml\n")),(0,l.kt)("p",null,"This will print the output of differences between deployed helm release and changes in specified ",(0,l.kt)("inlineCode",{parentName:"p"},"values.yaml")," file. Incase the output is empty, it means there is no difference/changes."),(0,l.kt)("h2",{id:"upgrading-helm-deployment"},"Upgrading Helm Deployment"),(0,l.kt)("p",null,"Once the local ",(0,l.kt)("inlineCode",{parentName:"p"},"values.yaml")," file is updated, it can be reflect to deployment using following commands:"),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre",className:"language-bash"},"helm upgrade [DEPLOYMENT_NAME] etherealengine/etherealengine --reuse-values -f [PATH_TO_VALUES_YAML]\n")),(0,l.kt)("p",null,"i.e."),(0,l.kt)("pre",null,(0,l.kt)("code",{parentName:"pre",className:"language-bash"},"helm upgrade dev etherealengine/etherealengine --reuse-values -f ~/etherealengine-ops/values/dev.ethereal.values.yaml\n")))}m.isMDXComponent=!0}}]);