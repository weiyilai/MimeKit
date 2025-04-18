﻿//
// DecoderFilter.cs
//
// Author: Jeffrey Stedfast <jestedfa@microsoft.com>
//
// Copyright (c) 2013-2025 .NET Foundation and Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

using System;

using MimeKit.Utils;
using MimeKit.Encodings;

namespace MimeKit.IO.Filters {
	/// <summary>
	/// A filter for decoding MIME content.
	/// </summary>
	/// <remarks>
	/// Uses a <see cref="IMimeDecoder"/> to incrementally decode data.
	/// </remarks>
	public class DecoderFilter : MimeFilterBase
	{
		/// <summary>
		/// Get the decoder used by this filter.
		/// </summary>
		/// <remarks>
		/// Gets the decoder used by this filter.
		/// </remarks>
		/// <value>The decoder.</value>
		public IMimeDecoder Decoder {
			get; private set;
		}

		/// <summary>
		/// Get the encoding.
		/// </summary>
		/// <remarks>
		/// Gets the encoding that the decoder supports.
		/// </remarks>
		/// <value>The encoding.</value>
		public ContentEncoding Encoding {
			get { return Decoder.Encoding; }
		}

		/// <summary>
		/// Initialize a new instance of the <see cref="DecoderFilter"/> class.
		/// </summary>
		/// <remarks>
		/// Creates a new <see cref="DecoderFilter"/> using the specified decoder.
		/// </remarks>
		/// <param name="decoder">A specific decoder for the filter to use.</param>
		/// <exception cref="System.ArgumentNullException">
		/// <paramref name="decoder"/> is <see langword="null"/>.
		/// </exception>
		public DecoderFilter (IMimeDecoder decoder)
		{
			if (decoder is null)
				throw new ArgumentNullException (nameof (decoder));

			Decoder = decoder;
		}

		/// <summary>
		/// Create a filter that will decode the specified encoding.
		/// </summary>
		/// <remarks>
		/// Creates a new <see cref="DecoderFilter"/> for the specified encoding.
		/// </remarks>
		/// <returns>A new decoder filter.</returns>
		/// <param name="encoding">The encoding to create a filter for.</param>
		public static IMimeFilter Create (ContentEncoding encoding)
		{
			switch (encoding) {
			case ContentEncoding.Base64: return new DecoderFilter (new Base64Decoder ());
			case ContentEncoding.QuotedPrintable: return new DecoderFilter (new QuotedPrintableDecoder ());
			case ContentEncoding.UUEncode: return new DecoderFilter (new UUDecoder ());
			default: return new PassThroughFilter ();
			}
		}

		/// <summary>
		/// Create a filter that will decode the specified encoding.
		/// </summary>
		/// <remarks>
		/// Creates a new <see cref="DecoderFilter"/> for the specified encoding.
		/// </remarks>
		/// <returns>A new decoder filter.</returns>
		/// <param name="name">The name of the encoding to create a filter for.</param>
		/// <exception cref="System.ArgumentNullException">
		/// <paramref name="name"/> is <see langword="null"/>.
		/// </exception>
		public static IMimeFilter Create (string name)
		{
			if (name is null)
				throw new ArgumentNullException (nameof (name));

			if (!MimeUtils.TryParse (name, out ContentEncoding encoding))
				encoding = ContentEncoding.Default;

			return Create (encoding);
		}

		/// <summary>
		/// Filter the specified input.
		/// </summary>
		/// <remarks>
		/// Filters the specified input buffer starting at the given index,
		/// spanning across the specified number of bytes.
		/// </remarks>
		/// <returns>The filtered output.</returns>
		/// <param name="input">The input buffer.</param>
		/// <param name="startIndex">The starting index of the input buffer.</param>
		/// <param name="length">The length of the input buffer, starting at <paramref name="startIndex"/>.</param>
		/// <param name="outputIndex">The output index.</param>
		/// <param name="outputLength">The output length.</param>
		/// <param name="flush">If set to <see langword="true" />, all internally buffered data should be flushed to the output buffer.</param>
		protected override byte[] Filter (byte[] input, int startIndex, int length, out int outputIndex, out int outputLength, bool flush)
		{
			EnsureOutputSize (Decoder.EstimateOutputLength (length), false);

			outputLength = Decoder.Decode (input, startIndex, length, OutputBuffer);
			outputIndex = 0;

			return OutputBuffer;
		}

		/// <summary>
		/// Reset the filter.
		/// </summary>
		/// <remarks>
		/// Resets the filter.
		/// </remarks>
		public override void Reset ()
		{
			Decoder.Reset ();
			base.Reset ();
		}
	}
}
