/*
* Copyright 2018-2022 TON DEV SOLUTIONS LTD.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.  You may obtain a copy of the
* License at:
*
* https://www.ton.dev/licenses
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and limitations
* under the License.
*/

use crate::error::NodeResult;
use crate::data::DocumentsDb;

use super::SerializedItem;

pub struct DocumentsDbMock;

impl DocumentsDb for DocumentsDbMock {
    fn put_account(&self, _: SerializedItem) -> NodeResult<()> {
        Ok(())
    }

    fn put_block(&self, _: SerializedItem) -> NodeResult<()> {
        Ok(())
    }

    fn put_message(&self, _: SerializedItem) -> NodeResult<()> {
        Ok(())
    }

    fn put_transaction(&self, _: SerializedItem) -> NodeResult<()> {
        Ok(())
    }

    fn has_delivery_problems(&self) -> bool {
        false
    }
}
