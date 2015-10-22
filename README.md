# MarkLogic-Element-Level-Security
MarkLogic Element Level Security solution that uses Semantics

# Objective
To create a model that will allow for a single document model that can support field level security by using document re-writing to redact protected values, while being able to produce facets where the values are protected at scale.  This approach is ok with search hits matching on restricted information (need to discover), but will not over-expose protected data during document retrieval or through faceted navigation.

# The Challenge
Several attempts have been made in various programs to use a single document model to contain the various classification levels of a document.  The idea is that a document would contain several fielded data points, where each data point needs to be protected at various protection levels.  The most common approach to solve this problem today is to create a separate duplicate copy of the document, one for each permutation of access control.  The problem with the current approach is that you end up with lots of duplication of data across many number of documents.  Due to the number of possible permutations of security controls in the US Government, it's not uncommon to have 20+ different security controls for a single document, which results in some values (the least protected values) being duplicated in each individual document.  This model can also run into facet count issues if some particular query happens to match on multiple of these documents that are intended to represent a single piece of data.

# The Idea
To help describe the solution, let's start with simple problem.  Let's say we have a single person who happens to have dual citizenship.  This person happens to have a citizenship in both the United States as well as Canada.  Let's say that the fact that the person has a Canada citizenship is protected at an Unclassified level, but the fact that the person is a United States citizen is protected at the Secret level.  We would like people with an Unclassified access level to be able to issue a search which returns this person, and have a citizenship facet with only the Canada value present.  If another user, with access to Secret level data, were to query the same set of data, we'd want the facet to contain both the Canada value as well as the United States value in the citizenship facet.

