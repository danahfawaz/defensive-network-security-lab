# Original lab configurations (Day-0 baseline)

These seven files are the device configurations of the original university
networking lab, extracted from its Packet Tracer 9.0 file. They are the input of
the first audit (`evidence/audit/00-original-lab/`) and show where the project
started:

* 4x Cisco 1841 routers running RIPv1 over `192.168.0.0/16` (/24 networks);
* 3x Cisco 2960-24TT switches with factory-default settings;
* every device keeps its default hostname (`Router` / `Switch`), so the files are
  named after the Packet Tracer device labels instead;
* no passwords, SSH, VLANs, ACLs, banners or logging.

The files contain no credentials and no personal data. They are kept unmodified
(apart from the comment header) so that the audit of the original state is
reproducible.
