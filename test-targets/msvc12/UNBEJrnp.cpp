#include <stdio.h>
#include <memory.h>

class one
{
	int x;
public:
	one():x(5)
	{
		printf("construct one\n");
	}

	virtual ~one()
	{
		printf("destruct one\n");

	}

	virtual int boo(){return 1;}
};

class two: public one
{
public:
	virtual int boo(){return 2;}
	virtual int foo(){return 22;}

	virtual ~two()
	{
		printf("destruct two\n");
	}

};


class three: public two
{
public:
	one a;
	two b;
	int c[20];
	int d;
	int e;

public:
	three():d(0),e(0){
		printf("construct three\n");
		memset(c,32,20*4);
	}

	virtual ~three()
	{
		printf("destruct three\n");

	}
	virtual int boo(){return 3;}
	virtual int foo(){return 33;}
	virtual int goo(){return 333;}
};


class four: public three
{
public:
	int a;
	int b;
	int c[20];
	int d;
	four():a(0),b(0),d(0)
	{
		printf("construct four\n");
		memset(c,33,20*4);
	}


	virtual ~four()
	{
		printf("destruct four\n");
	}
	virtual int boo(){return 4;}
	virtual int foo(){return 44;}
	virtual int goo(){return 444;}
};

class five: public four
{

};


struct base {
	int value;
	virtual void foo() { printf("base foo %d\n", value); }
	virtual void bar() { printf("base bar %d\n", value); }
};

struct offset {
	char space[10];
};

struct derived : offset, base {
	int dvalue;
	virtual void foo() {
		this->space[6] = 6;
		printf("derived foo %d\n", value); 
	}
};


void main()
{
	five stack_object;
	five *heap_object = new five();

	printf("%d\n",heap_object->boo());
	printf("%d\n",heap_object->foo());
	printf("%d\n",heap_object->goo());
	printf("%d\n", (*heap_object).three::boo());

	delete heap_object;

	derived * d = new derived();
	char chr = 'i';
	char *pchr = &chr;
	d->dvalue = 2;
	d->value = 1;
	d->space[0] = 0;
	d->space[2] = *pchr;
	d->space[5] = 5;
	d->space[9] = 9;
	d->foo();
	d->bar();

	delete d;
}