---
title: gVisor
layout: base
---

<div class="jumbotron jumbotron-fluid">
  <div class="container text-center">
     <p>Efficient defense-in-depth for container infrastructure anywhere.</p>
     <p style="margin-top: 20px;">
       <a class="btn" href="/docs/">Get Started&nbsp;<i class="fas fa-arrow-alt-circle-right ml-2"></i></a>
       <a class="btn btn-inverse" href="https://github.com/google/gvisor">GitHub&nbsp;<i class="fab fa-github ml-2"></i></a>
     </p>
  </div>
</div>

<div class="container"> <!-- Full page container. -->

<div class="row">
  <div class="col-sm-6 col-sm-push-6">
    <img src="/assets/images/packed_tetris.svg" width="300px" class="center-block" style="margin-top: 50px;" alt="Container resource model"/>
  </div>
  <div class="col-sm-6 col-sm-pull-6">
    <h2><a href="/docs/">gVisor</a> is a open-source container runtime for
    running sandboxed workloads safely and easily.</h2>

    <p>It provides each container with its own user space kernel, limiting the
    attack surface of the host. gVisor is a container-native technology,
    designed to improve container isolation without sacrificing the benefits of
    container efficiency and portability.</p>
  </div>
</div>

<h2>Features</h2>

<div class="row">

  <div class="col-md-4">
    <h4 id="seamless-security">Container-native Security</h4>
    <p>By providing each container with its own user-space kernel, gVisor
    provides protection against privilege escalations while still integrating
    seamlessly with popular container orchestration systems, such as Docker and
    Kubernetes. This includes support for advanced features, such as a volumes,
    terminals and sidecars.
    </p>
    <a class="button" href="/docs/architecture_guide/security/">Read More &raquo;</a>
  </div>

  <div class="col-md-4">
    <h4 id="resource-efficiency">Resource Efficiency</h4>
    <p>Containers are efficient because workloads of different shapes and sizes
    can be packed together by sharing host resources. By using host native
    abstractions such as threads and memory mappings, gVisor closely co-operates
    with the host to enable the same resource model as native containers.
    Sandboxed containers can safely and securely share host resources with each
    other and native containers on the same system.
    </p>
    <a class="button" href="/docs/architecture_guide/resources/">Read More &raquo;</a>
  </div>

  <div class="col-md-4">
    <h4 id="platform-portability">Platform Portability</h4>
    <p>Modern infrastructure spans multiple clouds and data centers, often using
    a mix of virtualized instances and traditional servers. The pluggable
    platform architecture of gVisor allows it to run anywhere, enabling security
    policies to be enforced consistently across multiple environments.
    Sandboxing requirements need not dictate where workloads can run.
    </p>
    <a class="button" href="/docs/architecture_guide/platforms/">Read More &raquo;</a>
  </div>
</div>

</div> <!-- container -->
