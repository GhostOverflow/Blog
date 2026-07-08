---
description: A deep dive into Windows Process architecture, its Lifecycle and abuse
icon: gears
cover: ../../.gitbook/assets/Gemini_Generated_Image_ilto6zilto6zilto.png
coverY: 54.46182728410507
---

# Part 1: Process Internals

### Introduction

From the previous post you should have enough Idea about how the whole Windows NT architecture is structured as a whole and why the Kernel mode and User mode separation is important for security.&#x20;

{% embed url="https://app.gitbook.com/o/Sd6j35iIkLfdCVutCP7r/s/e444gbpRwiAWKfgl85Jz/~/edit/~/changes/25/windows/windows-internals#user-mode-and-kernel-mode" %}

In this post we will dive into the hierarchy and abuse of Processes in Windows. There is a whole layer abstraction that a user doesn't see while normally using Windows and it is intentionally like that so user doesn't need to care about what is going under the hood. Process is a big topic so I will take it from the definition, explanation, components to usage of APIs and in the end we will discuss the offensive angle with tep going, this is shaping up finchnical insights.

### What is a Process

Many think that a process is just the "code running" and doing the tasks but it is not true. In-fact process is not even executing the code itself. This brings the question on what a process actually is then ?

In Windows a Process is just a set of resources allocated to an application to perform tasks. It holds the private address space, executable image, private handle table, access token and threads for the application that process belongs to. Together these resources form up a process that interacts with the kernel space through set of APIs.

{% embed url="https://learn.microsoft.com/en-us/windows/win32/procthread/about-processes-and-threads" %}

### Process Components

As a process consists of multiple components it is crucial to dive deeper into each of those to better understand a process

#### Private Address Space

When an executable is launched its code along with other memory related things like DLLs is loaded into a private memory space that is specifically allocated for that program. Every process has its own private space which is isolated and is not mixed up with other processes. [VMMap](https://learn.microsoft.com/en-us/sysinternals/downloads/vmmap) can show the private address space for a process as shown below.

<figure><img src="../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

For the example of this notepad application this private address space holds the temporary data that is being written in it along with its code. The memory concepts themselves will be covered in its own post as it is a much bigger topic and this is just for Private Address Space concept itself.

> **Note:** The private address space of a process is not the actual physical memory address but instead these are virtual addresses that are mapped to Physical addresses by the memory manager.

{% embed url="https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces" %}

#### Executable Image

Mostly Processes have an executable image associated with them that contains the initial code required by the application to start. It contains the main function, global variables and the main code for the application. The most common type of executable are the `.exe`  and `.dll` files that are mapped to a process when it runs. VMMap provides the images of a process as well.

<figure><img src="../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

The above example shows the list of images associated with the notepad process when its running. The most prominent one is the `notepad.exe` itself which initiates the process along with other common dll files needed by the program.

{% embed url="https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/executable-images" %}

#### Private Handle Table

Each process has a private handle table. It is an array of entries pointing to kernel objects (processes, threads, files, mutexes, etc). A handle itself is just an index into this table. When you open a handle (say via OpenProcess), the kernel checks your requested access rights against the target object's security descriptor, and if granted, caches that access mask on the handle entry. Every subsequent operation through that handle is checked against the cached mask, not re-checked against the object each time. [Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer) can be used to view the list of handles opened by a process

<figure><img src="../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

> **Note:** Handle value itself (like 0x4, 0x8) isn't the object's identity, it's a per-process index, meaning handle 0x4 in process A and 0x4 in process B point to totally different objects.

{% embed url="https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-handles" %}

#### Access Token

Whenever a process is created it has a set privileges that determine what a process is allowed to do on the system. These privileges are defined through a security kernel object known as Access Token. It contains the SID, User, Group, OS Privileges, Protection flag, session id, etc. Usually when a process is created it inherits the access token of the parent process. The access token of a process can be viewed in security tab of process properties in Process Explorer

<figure><img src="../../.gitbook/assets/image (6).png" alt=""><figcaption></figcaption></figure>

The access token granted to a process also depends upon the integrity that process runs as. A security mechanism called **Mandatory Integrity Control (MIC)** enforces the object access depending upon the integrity of the token. When a process runs normally by an administrative user it runs with a medium integrity token that is filtered by **UAC** that doesn't gives full administrative privileges to the process even if the user belonged to administrator group. If a high integrity token is needed to perform actions that require full administrative rights the **User Access Control (UAC)** mechanism is called which opens up a consent prompt to spawn process with elevated access. UAC requests a high integrity token from the OS and assigns it to the process which then allows the process to use all the administrative rights and privileges that were not available on medium integrity token.

{% embed url="https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens" %}
