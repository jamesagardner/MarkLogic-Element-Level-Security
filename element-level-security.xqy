xquery version "1.0-ml";

module namespace els = "http://marklogic.com/ps/element-level-security";

import module namespace sem = "http://marklogic.com/semantics" at "/MarkLogic/semantics.xqy";

declare namespace sec = "http://marklogic.com/xdmp/security";

declare function els:element-add-permission($element as element(), $permission as element(sec:permission))
{
	xdmp:node-replace($element, els:element-build-with-permission($element, $permission))
};

declare function els:element-build-with-permission($element as element(), $permission as element(sec:permission)) as element()
{
	element {fn:node-name($element)} {
		$element/node(),
	    <sem:triples>
      		<sem:subject>{els:subject-from-element($element)}</sem:subject>
      		<sem:predicate>{els:predicate-from-permission($permission)}</sem:predicate>
      		<sem:object>{fn:data($element)}</sem:object>
		</sem:triples>
	}
};

declare function els:redact($node as node(), $permissions as element(sec:permission)*) as node()?
{
	typeswitch ($node)
		case element() return
			if(els:has-permission($node, $permissions)) then
				element {fn:node-name($node)} { els:redact($node/(@*|node()), $permissions)}
			else
				()
		default return $node
};


declare private function els:has-permission($element as element(), $permissions as element(sec:permission)*) as xs:boolean
{
	if (els:is-protected-element($element)) then
		let $predicates := els:predicate-from-permission($permissions)
		let $subject := els:subject-from-element($element)
		return fn:exists($element/sem:triples[sem:subject = $subject and sem:predicate = $predicates])
	else
		fn:true()
};

declare private function els:is-protected-element($element as element()) as xs:boolean
{
	let $subject := els:subject-from-element($element)
	return
		fn:exists($element/sem:triples[sem:subject = $subject and 
			fn:starts-with(sem:predicate, "http://marklogic.com/ps/element-level-security/permission/role-id")])
};

declare private function els:subject-from-element($element as element()) as xs:string
{
	"http://marklogic.com/ps/element-level-security/qname/{" || fn:namespace-uri($element) || "}" || fn:local-name($element)
};


declare private function els:predicate-from-permission($permission as element(sec:permission)) as xs:string
{
	"http://marklogic.com/ps/element-level-security/permission/role-id/" || fn:data($permission/sec:role-id)
};
