#include <thread>
#include <bits/stdc++.h>
#include <ctime>
#include <unistd.h>
using namespace std;

void f(int t){
    printf("%d\n", t);
    for (int i = 0; i < 15; i++){
        printf("%d: Sleeping\n", i);
        sleep(1);
    }
}

int launching(){
    thread cur_thread(f, 1);
    cur_thread.detach();
    return 0;
}

int main(){
    int ret = launching();
    sleep(20);
    return 0;
}