# AuthZEN ⇄ Cedar マッピング定義一覧

このデモで Keycloak Authenticator が送る **AuthZEN リクエスト**が、cedar-agent 内で
どのように **Cedar の `principal` / `action` / `resource` / `context`** に変換され、
`policies/policies.json` のポリシーで評価されるかをまとめる。

変換ロジックの実体は `src/schemas/authzen.rs`（`EvaluationRequest::into_authorization_request`）、
リクエスト生成元は `authenticator/.../AuthZenAuthenticator.java`（`buildEvaluationRequest`）。

---

## 1. フィールド対応表（AuthZEN → Cedar）

| AuthZEN フィールド | Cedar での表現 | 変換規則 | 取得元（Authenticator） |
|---|---|---|---|
| `subject.type` + `subject.id` | `principal` = `<type>::"<id>"` | `build_euid(type, id)` で EntityUid 化 | `"User"` 固定 + `user.getUsername()` |
| `subject.properties.*` | `principal` エンティティの属性 | `properties` がリクエスト単位の追加エンティティ属性になる（`principal.<key>` で参照可） | user 属性 `user_type` / `organization` |
| `action.name` | `action` = `Action::"<name>"` | エンティティ型は `Action` 固定、id に `name` | authenticatorConfig `action`（default `login`） |
| `action.properties.*` | `action` エンティティ属性 | 同上（このデモでは未使用） | — |
| `resource.type` + `resource.id` | `resource` = `<type>::"<id>"` | `build_euid(type, id)` | authenticatorConfig `resourceType`（default `Client`）+ `clientId` |
| `resource.properties.*` | `resource` エンティティ属性 | 同上（このデモでは未使用） | — |
| `context.*` | Cedar `context` レコード | `Context::from_json_value` でそのまま投入（`context.<key>` で参照可） | `ip` / `access_route`（remote IP から分類） |

> **ポイント:** `subject.properties` / `resource.properties` は Cedar の「追加エンティティ」に
> 変換され、ポリシー内では `principal.user_type` のように **エンティティ属性**として参照する。
> 一方 `context` は**リクエストの context レコード**になり、`context.access_route` で参照する。
> 同じ「属性」でも参照経路（`principal.X` vs `context.X`）が異なる点に注意。

---

## 2. 具体的なリクエスト → エンティティ変換例

Authenticator が `alice` で `internal-portal` にログインしたときの送信ボディ:

```json
{
  "subject":  { "type": "User", "id": "alice",
                "properties": { "user_type": "employee", "organization": "acme" } },
  "action":   { "name": "login" },
  "resource": { "type": "Client", "id": "internal-portal" },
  "context":  { "ip": "192.168.65.1", "access_route": "internal" }
}
```

cedar-agent 内での評価対象:

| 役割 | Cedar 値 |
|---|---|
| `principal` | `User::"alice"`（属性 `user_type="employee"`, `organization="acme"`） |
| `action` | `Action::"login"` |
| `resource` | `Client::"internal-portal"` |
| `context` | `{ ip: "192.168.65.1", access_route: "internal" }` |

---

## 3. ポリシー定義一覧（`policies/policies.json`）

| ポリシー id | 対象 resource | 許可条件（when） | 参照する属性/コンテキスト |
|---|---|---|---|
| `internal-portal-policy` | `Client::"internal-portal"` | `principal.user_type == "employee"` かつ `context.access_route == "internal"` | `subject.properties.user_type` + `context.access_route` |
| `partner-portal-policy` | `Client::"partner-portal"` | `principal.user_type == "partner"` かつ `principal.organization == "globex"` | `subject.properties.user_type` + `subject.properties.organization` |
| `public-app-policy` | `Client::"public-app"` | 条件なし（認証済みなら全許可） | — |

Cedar 原文（`has` ガードで属性欠落時の評価エラーを回避）:

```cedar
// internal-portal-policy
permit(principal, action == Action::"login", resource == Client::"internal-portal")
when { principal has user_type && principal.user_type == "employee"
       && context.access_route == "internal" };

// partner-portal-policy
permit(principal, action == Action::"login", resource == Client::"partner-portal")
when { principal has user_type && principal.user_type == "partner"
       && principal has organization && principal.organization == "globex" };

// public-app-policy
permit(principal, action == Action::"login", resource == Client::"public-app");
```

> 明示的な `permit` に当たらないクライアント／属性の組み合わせはすべて **deny**（Cedar の
> default-deny）。`decision=false` を受けた Authenticator は `ACCESS_DENIED` でログインを拒否する。

---

## 4. 判定マトリクス（ローカルアクセス = `access_route: internal`）

| user \ client | `internal-portal` | `partner-portal` | `public-app` | 決定したポリシー |
|---|:---:|:---:|:---:|---|
| `alice` (employee / acme) | ✅ | ❌ | ✅ | internal-portal-policy / — / public-app-policy |
| `bob` (partner / globex)  | ❌ | ✅ | ✅ | — / partner-portal-policy / public-app-policy |
| `carol` (contractor / initech) | ❌ | ❌ | ✅ | — / — / public-app-policy |

各属性の出どころは realm の user 属性（`realm/authzen-demo-realm.json`）。
`access_route` は remote IP の分類で、外部アクセス時は `external` となり
`internal-portal-policy` の条件を満たさなくなる（alice でも internal-portal は deny）。

---

## 5. 属性の流れ（end-to-end）

```
Keycloak user 属性                 AuthZEN リクエスト              Cedar 評価
─────────────────                 ──────────────────             ──────────────
user_type = "employee"   ──▶  subject.properties.user_type  ──▶  principal.user_type
organization = "acme"    ──▶  subject.properties.organization──▶  principal.organization
(login 先 clientId)       ──▶  resource.id                    ──▶  resource == Client::"..."
remote IP 分類            ──▶  context.access_route           ──▶  context.access_route
(固定 "login")            ──▶  action.name                    ──▶  action == Action::"login"
```
