#include <iostream>
using namespace std;

int ret2(int a){
	return a * 2;
}

class A
{
	int a1;
public:
	virtual int A_virt1(int a, int b) {
		cout << "A_virt1 in A" << endl;
		return 1;
	}
	virtual int A_virt2(){
		cout << "A_virt2 in A" << endl;
		return 2;
	}
	static void A_static1() {
		cout << "A_static1 in A" << endl;
	}
	void A_simple1(int a, int b) {
		cout << "A_simple1 in A" << endl;
	}
};
class B
{
	int b1;
	int b2;
public:
	virtual int B_virt1(int a, int b) {
		cout << "B_virt1 in B" << endl;
		return 1;
	}
	virtual int B_virt2() {
		cout << "B_virt2 in B" << endl;
		return 2;
	}
};
class C : public A, public B
{
	int c1;
public:
	virtual int A_virt2() {
		cout << "A_virt2  in C" << endl;
		return 1;
	}
	virtual int B_virt2() {
		cout << "B_virt2 in C" << endl;
		return 2;
	}
};

int main() {
	A* pc = new C();
	B* pb = new B();
	A* pa = new A();
	
	cout << "pa->A_simple1(): ";
	pa->A_simple1(1,2);
	cout << "pa->A_static1(): ";
	pa->A_static1();
	cout << "pa->A_virt1(): ";
	pa->A_virt1(1,2);
	cout << "pa->A_virt2(): ";
	pa->A_virt2();
	
	cout << "pb->B_virt1(): ";
	pb->B_virt1(1,2);
	cout << "pb->B_virt2(): ";
	pb->B_virt2();

	cout << "pc->A_simple1(): ";
	pc->A_simple1(1,ret2(0));
	cout << "pc->A_static1(): ";
	pc->A_static1();
	cout << "pc->A_virt1(): ";
	pc->A_virt1(1,ret2(1));
	cout << "pc->A_virt2(): ";
	pc->A_virt2();
	return 0;
}