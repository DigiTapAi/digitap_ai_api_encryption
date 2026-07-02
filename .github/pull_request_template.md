### 🔍 Pull Request Overview

This PR addresses the following key features/fixes/updates:

* \[Brief 1-liner summary of what this PR does]

---

### ✅ Code Review Checklist

#### 1. 🔄 **Database Queries**

* [ ] Have all queries been optimized for performance (e.g., indexes, `SELECT` fields, query time)?
* [ ] Are queries free from **N+1 issues**, redundant DB hits, or unbounded record fetches?
* [ ] Are parameterized queries or ORM queries safeguarded against SQL injection?

#### 2. 🧠 **Business Logic**

* [ ] Is the logic flow clean, modular, and readable?
* [ ] Any areas where logic can be simplified or refactored for better maintainability?
* [ ] Are there any bottlenecks or loops over large datasets?

#### 3. 🧩 **Business Flow Validation**

* [ ] Does the logic correctly follow the product/business specification?
* [ ] Are all edge cases handled (nulls, empty states, retry scenarios, etc.)?
* [ ] During deployment, will it cause any interruption to the service or any dependent service(s)?

#### 4. 🔐 **Security Checks**

* [ ] Are all input parameters validated and sanitized?
* [ ] Are sensitive variables protected (e.g., secrets, tokens, PII data not logged)?
* [ ] Are role/access control validations in place where applicable?

#### 5. 🚨 **Silenced or Deferred Issues**

* [ ] Are there any TODOs, FIXME, or commented-out blocks?

  * If yes, please mention the: `[JIRA-TICKET-LINK]`
  * Justify if they're silenced intentionally and what's the plan for resolution in the ticket

#### 6. 📌 **JIRA Tickets Addressed**

* This PR resolves the following tickets:

  * ✅ \[JIRA-ID-1 Link]
  * ✅ \[JIRA-ID-2 Link]

---

### 🧪 Testing & QA

* [ ] Unit Tests written/updated
* [ ] Integration Test cases covered (DB, API, Auth flows, SDK Flow, Portal Flow)
* [ ] Test coverage: `__%`

---
### 👁️‍🗨️ Reviewer Closing Comments

* [Reviewer1 Name]: [Comment]
* [Reviewer2 Name]: [Comment]

---