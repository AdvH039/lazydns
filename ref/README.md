[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/ZqxmoA06)
# FILE: /dns-delay-injector/README.md
# DNS Query Delay Injector

## **Objective**
The goal of this assignment is to build a tool that can **introduce delays** in DNS query packets. These delays can be **user-defined** or **random**. The tool should provide filtering capabilities based on:
- **The container or process** making the DNS request
- **The target URL** being queried
- **The DNS server** handling the request

---

## **Repository Setup**
1. **Clone the repository:**
   ```sh
   git clone <repo-link>
   cd dns-delay-injector
   ```
2. **Modify and extend the provided template** according to the requirements.

---

## **Implementation Details**
- Use **eBPF** to intercept and manipulate DNS packets at the kernel level.
- Introduce configurable delays based on:
  - Process/container metadata
  - Specific DNS queries or domains
  - Specific DNS servers
- Implement a **user-space control program** using **libbpf, BCC, or Go eBPF**.
- Ensure the program allows users to specify delay times dynamically.
- Provide logging for debugging and verification.

---

## **Documentation Requirements**
Your submission must include:
- A **README.md** file with:
  - Clear setup and installation instructions
  - Usage examples and command-line arguments
  - Required dependencies and supported versions
- Well-documented code with meaningful comments.
- A script (`scripts/test.sh`) to test the delay functionality.

---

## **Repository Structure**
```
/ (Root)
│── README.md          # Detailed assignment instructions
│── Makefile           # Build and run commands
│── src/
│   │── main.c         # User-space control program
│   │── bpf_prog.c     # eBPF program to manipulate DNS packets
│── scripts/
│   │── test.sh        # Script to test the program
```

---

## **Submission Instructions**
1. Complete your implementation and ensure it meets the assignment requirements.
2. Update the `README.md` with detailed instructions on how to build and run your solution.
3. **Make a pull request (PR)** to submit your final code.
4. Your PR should include:
   - A description of your implementation.
   - Any limitations or known issues.
   - Example test cases showing how the delay is introduced.

**Happy coding! 🚀**