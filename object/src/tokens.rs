//! Conversion of DICOM objects into tokens.
use crate::mem::{InMemDicomObject, InMemElement};
use dicom_core::{dictionary::DataDictionary, DataElement, Tag};
use dicom_parser::dataset::{DataToken, IntoTokens, IntoTokensOptions};
use std::collections::VecDeque;

const SPECIFIC_CHARACTER_SET: Tag = Tag(0x0008, 0x0005);

/// A stream of tokens from a DICOM object.
pub struct InMemObjectTokens<E> {
    /// iterators of tokens in order of priority.
    tokens_pending: VecDeque<DataToken>,
    /// the iterator of data elements in order.
    elem_iter: E,
    /// whether the tokens are done
    fused: bool,
    /// Options to take into account when generating tokens
    token_options: IntoTokensOptions,
}

impl<E> InMemObjectTokens<E>
where
    E: Iterator,
{
    pub fn new<T>(obj: T) -> Self
    where
        T: IntoIterator<IntoIter = E, Item = E::Item>,
    {
        InMemObjectTokens {
            tokens_pending: Default::default(),
            elem_iter: obj.into_iter(),
            fused: false,
            token_options: Default::default(),
        }
    }

    pub fn new_with_options<T>(obj: T, token_options: IntoTokensOptions) -> Self
    where
        T: IntoIterator<IntoIter = E, Item = E::Item>,
    {
        InMemObjectTokens {
            tokens_pending: Default::default(),
            elem_iter: obj.into_iter(),
            fused: false,
            token_options,
        }
    }
}

impl<P, I, E> Iterator for InMemObjectTokens<E>
where
    E: Iterator<Item = DataElement<I, P>>,
    E::Item: IntoTokens,
{
    type Item = DataToken;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fused {
            return None;
        }

        // otherwise, consume pending tokens
        if let Some(token) = self.tokens_pending.pop_front() {
            return Some(token);
        }

        // otherwise, expand next element, recurse
        if let Some(elem) = self.elem_iter.next() {
            self.tokens_pending = if self.token_options == Default::default() {
                elem.into_tokens()
            } else {
                elem.into_tokens_with_options(self.token_options)
            }
            .collect();

            self.next()
        } else {
            // no more elements
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        // make a slightly better estimation for the minimum
        // number of tokens that follow: 2 tokens per element left
        (self.elem_iter.size_hint().0 * 2, None)
    }
}

impl<D> IntoTokens for InMemDicomObject<D> {
    type Iter = InMemObjectTokens<<InMemDicomObject<D> as IntoIterator>::IntoIter>;

    fn into_tokens(self) -> Self::Iter {
        InMemObjectTokens::new(self)
    }

    fn into_tokens_with_options(self, mut options: IntoTokensOptions) -> Self::Iter {
        //This is required for recursing with the correct option
        options.force_invalidate_sq_length |= self.charset_changed;
        InMemObjectTokens::new_with_options(self, options)
    }
}

impl<'a, D> IntoTokens for &'a InMemDicomObject<D>
where
    D: DataDictionary + Clone + 'a,
{
    type Iter = Box<dyn Iterator<Item = DataToken> + 'a>;

    fn into_tokens(self) -> Self::Iter {
        self.into_tokens_with_options(Default::default())
    }

    fn into_tokens_with_options(self, mut options: IntoTokensOptions) -> Self::Iter {
        options.force_invalidate_sq_length |= self.charset_changed;

        // When an element with a smaller tag than (0008,0005) exists (e.g. a
        // group-0x0000 sequence, which is non-conformant but accepted by the
        // lenient parser), emit (0008,0005) first so the written file declares
        // the charset before those items. Without this the decoder for the
        // re-read file encounters the sequence before learning the charset and
        // uses the wrong codec for any text inside.
        let needs_reorder = self.element(SPECIFIC_CHARACTER_SET).is_ok()
            && self
                .iter()
                .next()
                .map(|e| e.header().tag < SPECIFIC_CHARACTER_SET)
                .unwrap_or(false);

        if needs_reorder {
            let cs_elem: InMemElement<D> =
                self.element(SPECIFIC_CHARACTER_SET).unwrap().clone();
            let cs_tokens: Vec<DataToken> =
                cs_elem.into_tokens_with_options(options).collect();
            let rest: Vec<InMemElement<D>> = self
                .into_iter()
                .filter(|e| e.header().tag != SPECIFIC_CHARACTER_SET)
                .cloned()
                .collect();
            Box::new(
                cs_tokens
                    .into_iter()
                    .chain(InMemObjectTokens::new_with_options(rest, options)),
            )
        } else {
            Box::new(InMemObjectTokens::new_with_options(
                self.into_iter().cloned(),
                options,
            ))
        }
    }
}
