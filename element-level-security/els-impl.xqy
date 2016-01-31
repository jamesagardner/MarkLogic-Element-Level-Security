xquery version "1.0-ml";

module namespace elsi = "http://marklogic.com/ps/element-level-security/impl";

import module namespace sem = "http://marklogic.com/semantics" at "/MarkLogic/semantics.xqy";

declare namespace sec = "http://marklogic.com/xdmp/security";

declare variable $default-options := 
	<elsi:options>
		<elsi:remove-permissions>true</elsi:remove-permissions>
	</elsi:options>;

declare function elsi:element-add-permission($element as element(), $permission as element(sec:permission))
{
	xdmp:node-replace($element, elsi:element-build-with-permission($element, $permission))
};

declare function elsi:element-build-with-permission($element as element(), $permission as element(sec:permission)) as element()
{
	element {fn:node-name($element)} {
		$element/node(),
	    <sem:triples>
	    	<sem:triple>
      			<sem:subject>{elsi:subject-from-element($element)}</sem:subject>
      			<sem:predicate>{elsi:predicate-from-permission($permission)}</sem:predicate>
      			<sem:object>{fn:data($element)}</sem:object>
      		</sem:triple>
		</sem:triples>
	}
};

declare function elsi:redact($node as node(), $permissions as element(sec:permission)*) as node()?
{
	elsi:redact($node, $permissions, $default-options)
};

declare private function elsi:redact($node as node(), $permissions as element(sec:permission)*, $options as element(elsi:options)) as node()? {
	typeswitch ($node)
	case element() return
		if(elsi:has-permission($node, $permissions)) then
			if (elsi:is-protected-element($node) and $options/elsi:remove-permissions/xs:boolean(.)) then
				element {fn:node-name($node)} {
					elsi:redact($node/(@*|node()) except $node/sem:triples[sem:triple/sem:subject = elsi:subject-from-element($node)], $permissions, $options)
				}
			else
				element {fn:node-name($node)} {elsi:redact($node/(@*|node()), $permissions, $options)}
		else
			()
	case document-node() return
		document {elsi:redact($node/node(), $permissions, $options)}
	default return $node
};


declare private function elsi:has-permission($element as element(), $permissions as element(sec:permission)*) as xs:boolean
{
	if (elsi:is-protected-element($element)) then
		let $predicates := elsi:predicate-from-permission($permissions)
		let $subject := elsi:subject-from-element($element)
		return fn:exists($element/sem:triples/sem:triple[sem:subject = $subject and sem:predicate = $predicates])
	else
		fn:true()
};

declare private function elsi:is-protected-element($element as element()) as xs:boolean
{
	let $subject := elsi:subject-from-element($element)
	return
		fn:exists($element/sem:triples/sem:triple[sem:subject = $subject and 
			fn:starts-with(sem:predicate, "http://marklogic.com/ps/element-level-security/permission/role-id")])
};

declare function elsi:subject-from-element($element as element()) as sem:iri
{
	elsi:subject-from-qname(fn:node-name($element))
};

declare function elsi:subject-from-qname($qname as xs:QName) as sem:iri
{
	sem:iri("http://marklogic.com/ps/element-level-security/qname/{" || fn:namespace-uri-from-QName($qname) || "}" || fn:local-name-from-QName($qname))
};

declare function elsi:predicate-from-permission($permission as element(sec:permission)) as sem:iri
{
	sem:iri("http://marklogic.com/ps/element-level-security/permission/role-id/" || fn:data($permission/sec:role-id))
};
