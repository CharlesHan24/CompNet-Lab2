// using_declaration3.cpp
#include <stdio.h>

namespace A{
    int abc;
    void func();
}

namespace B {
   using A::abc;// A's g is now visible as X::g
   using A::func;
}

namespace C{
    using A::abc;
    using A::func;

    void f(){
        abc += 1;
        func();
    }
}

namespace A{
    void func(){
        abc += 55;
    }
}


int main() {
    C::f();
    printf("%d\n", A::abc);
}