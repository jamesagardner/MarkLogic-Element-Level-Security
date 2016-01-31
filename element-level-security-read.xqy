xquery version "1.0-ml";

module namespace els = "http://marklogic.com/ps/element-level-security";

import module namespace sem = "http://marklogic.com/semantics" at "/MarkLogic/semantics.xqy";
import module namespace els = "http://marklogic.com/ps/element-level-security" at "element-level-security.xqy";

declare namespace sec = "http://marklogic.com/xdmp/security";

declare function els:doc($uri as xs:string*, $permissions as element(sec:permission)*) as document-node()*
{
	els:redact(fn:doc($uri), $permissions)
};

declare function els:element-values($element-names as xs:QName*, $permissions as element(sec:permission)*)  as xs:anyAtomicType* {
	els:element-values($element-names, (), (), (), (), (), $permissions)
};

declare function els:element-values($element-names as xs:QName*, $start as xs:anyAtomicType?, $permissions as element(sec:permission)*) as xs:anyAtomicType* {
	els:element-values($element-names, $start, (), (), (), (), $permissions)
};

declare function els:element-values($element-names as xs:QName*, $start as xs:anyAtomicType?, $options as xs:string*, $permissions as element(sec:permission)*) as xs:anyAtomicType* {
	els:element-values($element-names, $start, $options, (), (), (), $permissions)
};

declare function els:element-values($element-names as xs:QName*, $start as xs:anyAtomicType?, $options as xs:string*, $query as cts:query?, $permissions as element(sec:permission)*) as xs:anyAtomicType* {
	els:element-values($element-names, $start, $options, $query, (), (), $permissions)
};

declare function els:element-values($element-names as xs:QName*, $start as xs:anyAtomicType?, $options as xs:string*, $query as cts:query?, $quality-weight as xs:double?, $permissions as element(sec:permission)*) as xs:anyAtomicType* {
	els:element-values($element-names, $start, $options, $query, $quality-weight, (), $permissions)
};

declare function els:element-values($element-names as xs:QName*, $start as xs:anyAtomicType?, $options as xs:string*, $query as cts:query?, $quality-weight as xs:double?, $forest-ids as xs:unsignedLong*, $permissions as element(sec:permission)*) as xs:anyAtomicType* {
	let $triples := cts:triples(els:subject-from-qname($element-names), els:predicate-from-permission($permissions), $start, $start ! ">=", $options, $query, $forest-ids)
	return document {$triples}/sem:triple/sem:object/node()
};
