#ifndef REFCOUNTSTRING_H
#define REFCOUNTSTRING_H

#include <cstdlib>
#include <cstring>

// A simple reference-counted C string, intended to be used through a pointer
// as RefCountString * with manual management of the reference count in order
// to stay a POD (for use in unions). For the same reason, constructors are
// static. The wrapper RefCountStringHandle can be used where automatic
// reference handling is possible.
struct RefCountString
{
    // data
    int count;
    char data[sizeof(int)]; // this is a dummy, actual array will be larger


    // implementation
    void inc_refcount()
    {
        count += 1;
    }

    void dec_refcount()
    {
        count -= 1;
        if (count == 0)
            std::free(this);
    }

    static RefCountString *allocate(int data_length)
    {
        std::size_t size =
            sizeof(RefCountString) - sizeof(char[sizeof(int)]) + data_length * sizeof(char);

        void *chunk = std::malloc(size);
        if (!chunk)
            throw std::bad_alloc();

        RefCountString *new_str = static_cast<RefCountString *>(chunk);
        new_str->count = 1;
        return new_str;
    }

    static RefCountString *construct(const char *c_string)
    {
        std::size_t length = std::strlen(c_string);
        RefCountString *str = RefCountString::allocate(length + 1);
        std::memcpy(str->data, c_string, length + 1);
        return str;
    }

    static RefCountString *construct(const char *data, int from, int to)
    {
        int length = to - from;
        if (length < 0)
            length = 0;
        RefCountString *str = RefCountString::allocate(length + 1);
        std::memcpy(str->data, data + from, length);
        str->data[length - 1 + 1] = '\0';
        return str;
    }
};

class RefCountStringHandle
{
public:
    RefCountStringHandle()
    {
        value = 0;
    }

    RefCountStringHandle(RefCountString *str)
    {
        value = str;
    }

    ~RefCountStringHandle()
    {
        if (value)
            value->dec_refcount();
    }

    RefCountString *operator *()
    {
        return value;
    }

    void set(RefCountString *str)
    {
        if (value != str)
        {
            if (value)
                value->dec_refcount();
            value = str;
        }
    }

    RefCountString *value;
};


#endif
