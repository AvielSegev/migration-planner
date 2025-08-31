# 🛠️ Prerequisites

* **Ensure the OpenShift internal registry is initialized (steps below).**

---

### 🔑 Login to your cluster

---

### 📦 Install the MTV Operator

1. Navigate to **Operators → OperatorHub**
2. Search for **Migration Toolkit for Virtualization Operator** and click **Install**
3. Click **Create ForkliftController** → this will initialize the operator
4. After a few moments, you’ll see **Migration for Virtualization** added to the menu in the UI

---

### 📦 Install the OpenShift Virtualization Operator

1. Navigate to **Operators → OperatorHub**
2. Search for **OpenShift Virtualization** and click **Install**
3. Click **Create instance** of OpenShift Virtualization Deployment and HostPathProvisioner Deployment → this will initialize the operator
4. After a few moments, you’ll see **Virtualization** added to the menu in the UI

---

### 🌐 Configure the Provider

1. Go to **Migration for Virtualization → Providers**
2. Click **Create provider**
3. Select **VMware**
4. Assign a name and provide the URL
5. Download the **VDDK file** corresponding to your VMware version from:  
   👉 https://developer.broadcom.com/sdks/vmware-virtual-disk-development-kit-vddk/latest


------------------------FIXME------------------------------
6. browse the downloaded file
7. Enter the username and password for the desired vmware environment
8. Press: Create provider
9. Create also another provider for the destination from type openshift-virtualization
---

### Create migration plan

1. Go to **Migration for Virtualization → Migration plans**
2. Click **Create plan**
3. Assign a name
4. Select the source and destination pre-configured providers

------------------------FIXME------------------------------

---

## 🏗️ Ensure the OpenShift Internal Registry Is Initialized

Run:

```bash
oc get configs.imageregistry.operator.openshift.io/cluster -o jsonpath='{.spec.managementState}'
```

If the returned value is Removed, it means the cluster does not have the internal registry initialized.

Two options are available:

1️⃣ Recommended: Initialize with PVC

Save the following to a file named registry-pvc.yaml:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
    name: registry-storage
    namespace: openshift-image-registry
spec:
    accessModes:
        - ReadWriteOnce
    resources:
        requests:
            storage: 5Gi
    storageClassName: lvms-vg1  # Replace with your StorageClass name
```

Apply the PVC:

```bash
oc apply -f registry-pvc.yaml
```

Patch the registry config:

```bash
oc patch configs.imageregistry.operator.openshift.io/cluster \
--type=merge \
-p '{
    "spec": {
        "managementState": "Managed",
        "rolloutStrategy": "Recreate",
        "storage": {
            "pvc": {
                "claim": "registry-storage"
            }
        }
    }
}'
```

2️⃣ Alternative: Initialize with EmptyDir (not persistent)

```bash
oc patch configs.imageregistry.operator.openshift.io/cluster \
--type=merge \
-p '{
    "spec": {
        "managementState": "Managed",
        "storage": {
        "emptyDir": {}
        }
    }
}'
```