{{- define "beyric-app.imageTag" -}}
{{- if .Values.image.tag -}}{{ .Values.image.tag }}
{{- else if .Values.imageTagKey -}}{{ (index .Values .Values.imageTagKey).tag | required (printf "images.yaml has no .%s.tag" .Values.imageTagKey) }}
{{- else -}}{{ fail "set image.tag or imageTagKey" }}{{- end -}}
{{- end -}}

{{- define "beyric-app.image" -}}
{{ .Values.image.repository | required "image.repository is required" }}:{{ include "beyric-app.imageTag" . }}
{{- end -}}

{{- define "beyric-app.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/part-of: {{ .root.Release.Name }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
{{- end -}}

{{- define "beyric-app.selector" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
{{- end -}}

{{/* Vault Agent annotations. .mode = "sidecar" | "init" */}}
{{- define "beyric-app.vaultAnnotations" -}}
{{- $v := .root.Values.vaultAgent -}}
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/role: {{ .role | quote }}
vault.hashicorp.com/agent-inject-secret-{{ $v.fileName }}: {{ .credsPath | quote }}
vault.hashicorp.com/agent-inject-template-{{ $v.fileName }}: |
  {{`{{- with secret "`}}{{ .credsPath }}{{`" -}}`}}
  DATABASE_URL=postgresql://{{`{{ .Data.username }}`}}:{{`{{ .Data.password }}`}}@{{ $v.dbHost }}:{{ $v.dbPort }}/{{ $v.dbName }}?sslmode={{ $v.sslmode }}
  {{`{{- end }}`}}
vault.hashicorp.com/agent-limits-mem: {{ $v.resources.limits.memory | quote }}
vault.hashicorp.com/agent-requests-cpu: {{ $v.resources.requests.cpu | quote }}
vault.hashicorp.com/agent-requests-mem: {{ $v.resources.requests.memory | quote }}
vault.hashicorp.com/agent-run-as-same-user: "true"
{{- if eq .mode "init" }}
vault.hashicorp.com/agent-pre-populate-only: "true"
{{- else }}
vault.hashicorp.com/agent-pre-populate: "false"
vault.hashicorp.com/agent-inject-command-{{ $v.fileName }}: {{ $v.restartCommand | quote }}
{{- end }}
{{- end -}}

{{/* Boolean with a true default: Sprig's `default` treats false as empty, so use hasKey. */}}
{{- define "beyric-app.enabled" -}}
{{- if hasKey . "enabled" }}{{ .enabled }}{{ else }}true{{ end -}}
{{- end -}}
