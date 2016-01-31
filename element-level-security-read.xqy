xquery version "1.0-ml";

module namespace els = "http://marklogic.com/ps/element-level-security";

import module namespace sem = "http://marklogic.com/semantics" at "/MarkLogic/semantics.xqy";
import module namespace els = "http://marklogic.com/ps/element-level-security" at "element-level-security.xqy";

declare namespace sec = "http://marklogic.com/xdmp/security";

declare function els:doc($uri as xs:string*, $permissions as element(sec:permission)) as document-node()*
{
	els:redact(fn:doc($uri), $permissions)
};
