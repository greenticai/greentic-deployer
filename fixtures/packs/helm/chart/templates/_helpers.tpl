{{- define "greentic-operator.name" -}}
greentic-operator
{{- end -}}

{{- define "greentic-operator.fullname" -}}
{{ include "greentic-operator.name" . }}
{{- end -}}

