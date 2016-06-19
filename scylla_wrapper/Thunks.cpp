#include "stdafx.h"
#include "Thunks.h"

void ImportThunk::invalidate()
{
    ordinal = 0;
    hint = 0;
    valid = false;
    suspect = false;
    moduleName[0] = 0;
    name[0] = 0;
}

bool ImportModuleThunk::isValid() const
{
    std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin();
    while (iterator != thunkList.end())
    {
        if (iterator->second.valid == false)
        {
            return false;
        }
        iterator++;
    }

    return true;
}

DWORD_PTR ImportModuleThunk::getFirstThunk() const
{
    if (thunkList.size() > 0)
    {
        const std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin();
        return iterator->first;
    }
    else
    {
        return 0;
    }
}