import { createSlice } from '@reduxjs/toolkit';

export const fileSlice = createSlice({
    name: 'file',
    initialState: {
        files: [],
    },
    reducers: {
        addFile: (state, action) => {
            state.files.push(action.payload);
        },
    },
});

export const { addFile } = fileSlice.actions;
export default fileSlice.reducer;