xquery version "1.0-ml";

module namespace els = "http://marklogic.com/ps/element-level-security";

import module namespace sem = "http://marklogic.com/semantics" at "/MarkLogic/semantics.xqy";

declare namespace sec = "http://marklogic.com/xdmp/security";

declare function els:element-add-permission($element as element(), $permission as element(sec:permission))
{
	xdmp:node-replace($element, els:element-build-with-permission($element, $permission))
};

declare function els:element-build-with-permission($element as element(), $permission as element(sec:permission))
{
	element {fn:node-name($element)} {
		$element/node(),
	    <sem:triples>
      		<sem:subject>http://marklogic.com/ps/element-level-security/qname/{{{fn:namespace-uri($element)}}}{fn:local-name($element)}</sem:subject>
      		<sem:predicate>http://marklogic.com/ps/element-level-security/permission/role-id/{fn:data($permission/sec:role-id)}</sem:predicate>
      		<sem:object>{fn:data($element)}</sem:object>
		</sem:triples>
	}
};
