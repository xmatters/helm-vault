{{- define "version" -}}
{{- if .Values.version -}}
{{ .Values.version | replace "." "-" }}
{{- else if .Values.branch -}}
{{ .Values.branch }}
{{- else -}}
{{ .Release.Name | replace "." "-" }}
{{- end -}}
{{- end -}}

{{- define "googleBucketName" -}}
{{- if .Values.googleBucketName -}}
{{ .Values.googleBucketName }}
{{- else -}}
{{ .Values.googleBucketNamePrefix }}-{{ .Values.environment }}
{{- end -}}
{{- end -}}

{{- define "name" -}}
flagrunner-{{ .Values.environment }}-{{ .Values.region | replace "-" "" }}-{{ .Values.version }}
{{- end -}}