package kubernetes.deployment

deny[msg] {
  input.kind == "Deployment"
  input.spec.strategy.type != "RollingUpdate"
  msg := "Deployment must use RollingUpdate strategy"
}

deny[msg] {
  input.kind == "Deployment"
  replicas := input.spec.replicas
  replicas < 2
  msg := "Replicas must be >= 2"
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  endswith(container.image, ":latest")
  msg := sprintf("Container %v uses latest tag", [container.name])
}

deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  not container.livenessProbe
  msg := sprintf("Container %v missing livenessProbe", [container.name])
}
