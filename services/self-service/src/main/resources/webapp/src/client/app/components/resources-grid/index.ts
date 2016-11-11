/******************************************************************************************************

Copyright (c) 2016 EPAM Systems Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*****************************************************************************************************/

import { NgModule, Component } from "@angular/core";
import { CommonModule } from "@angular/common";
import { ResourcesGrid } from "./resources-grid.component";
import { ComputationalResourcesModule } from './../computational-resources-list/index';
import { ModalModule } from './../modal/index';
import { ComputationalResourceCreateDialogModule } from './../computational-resource-create-dialog/index';
import { ConfirmationDialogModule } from './../confirmation-dialog/index';
import { DetailDialogModule } from './../detail-dialog/index';

export * from "./resources-grid.component";

@NgModule({
  imports: [CommonModule, ComputationalResourcesModule, ModalModule, ConfirmationDialogModule, DetailDialogModule, ComputationalResourceCreateDialogModule],
  declarations: [ResourcesGrid],
  exports: [ResourcesGrid]
})

export class ResourcesGridModule { }
