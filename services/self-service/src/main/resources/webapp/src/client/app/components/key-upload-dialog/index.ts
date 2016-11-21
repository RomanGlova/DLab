/***************************************************************************

Copyright (c) 2016, EPAM SYSTEMS INC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

****************************************************************************/

import {NgModule, Component} from "@angular/core";
import {CommonModule} from "@angular/common";
import {ModalModule} from './../modal/index';
import {UploadKeyDialog} from "./key-upload-dialog.component";

export * from "./key-upload-dialog.component";

@NgModule({
  imports: [CommonModule, ModalModule],
  declarations: [UploadKeyDialog],
  exports: [UploadKeyDialog]
})

export class UploadKeyDialogModule { }
