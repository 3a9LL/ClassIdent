#include <iostream>
#include <string>
using namespace std;

class Circle {         // classname
private:
	double radius;      // Data members (variables)
	string color;

public:
	Circle(double r = 1.0, string c = "none") {
		this->radius = r;
		this->color = c;
	}
	double getRadius() {
		return this->radius;
	} // Member functions
	double getArea() {
		double r = this->radius;
		return 3.14*r*r;
	}
};

int main() {
	Circle c1 = Circle(1.2, "red");  // radius, color
	Circle c2 = Circle(3.4);         // radius, default color
	Circle c3 = Circle();            // default radius and color
	cout << c1.getArea() << endl;
	cout << c2.getArea() << endl;
	return 0;
}
