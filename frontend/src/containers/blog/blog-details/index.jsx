import PropTypes from "prop-types";
import { Link } from "react-router-dom";
import SwiperCore, { Pagination } from "swiper";
import { Swiper, SwiperSlide } from "swiper/react";
import BlogTag from "../../../components/blog/blog-tag";
import Comment from "../../../components/comment";
import { slugify } from "../../../utils";

SwiperCore.use([Pagination]);

const BlogDetailsContainer = ({ data }) => {
    const cate = data.categories.map((value, i) => {
        return (
            <Link
                className="category"
                to={process.env.PUBLIC_URL + `/category/${slugify(value)}`}
                key={i}
            >
                {value}
                {i !== data.categories.length - 1 && ","}
            </Link>
        );
    });
    return (
        <div className="blog-details-area">
            <div className="post-details-content">
                {data?.format === "slider" && (
                    <div className="post-media">
                        <Swiper
                            className="post-gallery"
                            spaceBetween={0}
                            slidesPerView={1}
                            loop
                            pagination={{ clickable: true }}
                        >
                            {data.sliderThumb &&
                                data.sliderThumb.map((single, key) => {
                                    return (
                                        <SwiperSlide key={key}>
                                            <img
                                                key={key}
                                                src={`${process.env.PUBLIC_URL}/${single.image}`}
                                                alt="Alexis"
                                            />
                                        </SwiperSlide>
                                    );
                                })}
                        </Swiper>
                    </div>
                )}
                {data?.format === "thumbnail" && (
                    <div className="post-media">
                        <img
                            src={`${process.env.PUBLIC_URL}/${data.media.images}`}
                            alt="Alexis"
                        />
                    </div>
                )}
                {data?.format === "audio" && (
                    <div className="post-audio audio-details">
                        <div className="embed-responsive">
                            <iframe
                                title="title"
                                src={`${process.env.PUBLIC_URL}/${data.audioSrc}`}
                            ></iframe>
                        </div>
                    </div>
                )}
                {data?.format === "quote" && (
                    <div className="blog-quote">
                        <div className="overlay-content">
                            <div className="quotes">
                                <div className="icon">
                                    <i className="icon_quotations"></i>
                                </div>
                                <p>{data.quoteContent}</p>
                                <div className="name">- Chirs Ivan -</div>
                            </div>
                        </div>
                    </div>
                )}
                <div className="post-details-body">
                    <div className="bread-crumbs">
                        <Link to={process.env.PUBLIC_URL + "/"}>Home</Link>
                        <span>&#8250;</span>
                        <Link to={process.env.PUBLIC_URL + "/blog"}>Blog</Link>
                        <span>&#8250;</span>
                        <span className="active">{data.title}</span>
                    </div>
                    <div className="content">
                        <h2 className="title">{data.title}</h2>

                        <div className="meta">
                            <Link
                                className="post-date"
                                to={
                                    process.env.PUBLIC_URL +
                                    `/date/${slugify(data.date)}`
                                }
                            >
                                <i className="icon_calendar"></i> {data.date}
                            </Link>{" "}
                            <span>|</span>{" "}
                            <Link
                                className="author"
                                to={
                                    process.env.PUBLIC_URL +
                                    `/author/${slugify(data.author)}`
                                }
                            >
                                <i className="icon icofont-user-alt-3"></i>{" "}
                                {data.author}
                            </Link>{" "}
                            <span>|</span>{" "}
                            <span className="cate-wrap">
                                <i className="icon_folder-alt"></i>
                                {cate}
                            </span>{" "}
                            <span>|</span>{" "}
                            <span className="comments-count">
                                <i className="icon_chat_alt"></i> 02 Comments
                            </span>
                        </div>

                        {data.body.map((value, i) => {
                            return (
                                <div
                                    key={i}
                                    className="desc"
                                    dangerouslySetInnerHTML={{ __html: value }}
                                />
                            );
                        })}
                    </div>
                    <BlogTag />
                    <div className="social-icons">
                        <span>Share:</span>
                        <a
                            href="https://www.facebook.com/"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            <i className="icofont-facebook"></i>
                        </a>
                        <a
                            href="https://twitter.com/"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            <i className="icofont-twitter"></i>
                        </a>
                        <a
                            href="https://www.pinterest.com"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            <i className="social_pinterest"></i>
                        </a>
                        <a
                            href="https://www.instagram.com/"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            <i className="icofont-instagram"></i>
                        </a>
                        <a
                            href="https://rss.com/"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            <i className="social_rss"></i>
                        </a>
                    </div>
                    <div className="comment-area">
                        <h4 className="title">Leave a comment</h4>
                        <div className="comment-form-wrap">
                            <Comment url="" id={data.id} title={data.title} />
                        </div>
                    </div>
                </div>
            </div>

            <div className="blog-navigation">
                <div className="prev">
                    <Link to={process.env.PUBLIC_URL + "/"}>
                        Newer post <i className="icofont-arrow-right"></i>
                    </Link>
                </div>
                <div className="next">
                    <Link to={process.env.PUBLIC_URL + "/"}>
                        Oldest post <i className="icofont-arrow-right"></i>
                    </Link>
                </div>
            </div>
        </div>
    );
};

BlogDetailsContainer.propTypes = {
    data: PropTypes.object,
};

export default BlogDetailsContainer;
